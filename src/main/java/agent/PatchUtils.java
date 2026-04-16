package agent;

import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

public class PatchUtils {

    static final String HELPER =
            "net/mcreator/transfinityimproved/coremod/PreatorGodHelper";

    // ── disableMyLib2: wipe only the specific hostile methods ─────────────────
    public static byte[] disableMyLib2(byte[] bytes) {
        ClassNode cn = new ClassNode();
        new ClassReader(bytes).accept(cn, 0);

        for (MethodNode m : cn.methods) {
            if (m.name.contains("stopBadThreads")
                    || m.name.contains("killOtherXform")
                    || m.name.contains("keepKilling")) {

                m.instructions.clear();
                m.instructions.add(new InsnNode(Opcodes.RETURN));
            }
        }

        ClassWriter cw = new ClassWriter(0);
        cn.accept(cw);
        return cw.toByteArray();
    }

    // ── emptyClass: BUG FIX — handle ALL return types, not just void/boolean ──
    public static byte[] emptyClass(byte[] bytes) {
        ClassNode cn = new ClassNode();
        new ClassReader(bytes).accept(cn, 0);

        for (MethodNode m : cn.methods) {
            // Leave constructors alone so the class can still be instantiated
            if (m.name.equals("<init>") || m.name.equals("<clinit>")) continue;

            m.instructions.clear();
            m.tryCatchBlocks.clear(); // clear try/catch too or ASM gets confused

            // Use the actual return type from the descriptor
            // e.g. "(IF)Z" → return type is Z (boolean)
            String returnDesc = m.desc.substring(m.desc.lastIndexOf(')') + 1);
            switch (returnDesc) {
                case "V":                                             // void
                    m.instructions.add(new InsnNode(Opcodes.RETURN));
                    break;
                case "Z": case "B": case "C": case "S": case "I":   // int-family + boolean
                    m.instructions.add(new InsnNode(Opcodes.ICONST_0));
                    m.instructions.add(new InsnNode(Opcodes.IRETURN));
                    break;
                case "J":                                             // long
                    m.instructions.add(new InsnNode(Opcodes.LCONST_0));
                    m.instructions.add(new InsnNode(Opcodes.LRETURN));
                    break;
                case "F":                                             // float
                    m.instructions.add(new InsnNode(Opcodes.FCONST_0));
                    m.instructions.add(new InsnNode(Opcodes.FRETURN));
                    break;
                case "D":                                             // double
                    m.instructions.add(new InsnNode(Opcodes.DCONST_0));
                    m.instructions.add(new InsnNode(Opcodes.DRETURN));
                    break;
                default:                                              // Object / array
                    m.instructions.add(new InsnNode(Opcodes.ACONST_NULL));
                    m.instructions.add(new InsnNode(Opcodes.ARETURN));
                    break;
            }

            // Reset stack/locals so ASM doesn't reject the rewritten method
            m.maxStack  = 2;
            m.maxLocals = m.maxLocals == 0 ? 1 : m.maxLocals;
        }

        ClassWriter cw = new ClassWriter(0);
        cn.accept(cw);
        return cw.toByteArray();
    }

    // ── patchLivingEntity: god mode hooks ────────────────────────────────────
    public static byte[] patchLivingEntity(byte[] bytes) {
        ClassNode cn = new ClassNode();
        new ClassReader(bytes).accept(cn, 0);

        for (MethodNode m : cn.methods) {
            switch (m.name) {
                // ── already covered ──────────────────────────────────────────
                case "m_6469_": injectCancelBoolean(m); break; // hurt()
                case "m_6478_": injectCancelVoid(m);    break; // heal (or similar)
                case "m_6667_": injectDiePatch(m);      break; // die()
                case "m_6675_":                                // knockback
                case "m_8077_": injectCancelVoid(m);    break; // forceKill or similar

                // ── isDeadOrDying → always return false ──────────────────────
                case "m_6060_": injectIsDead(m);        break;

                // ── NEW: actuallyHurt() — raw damage AFTER armor/resistance ──
                // This fires even if hurt() is cancelled by another mod,
                // so blocking it is a second layer of protection.
                // Does NOT touch setHealth — it just returns early.
                case "m_21051_": injectCancelVoid(m);   break;

                // ── NEW: kill() — /kill command and instant-kill sources ──────
                // Just returns early; health stays wherever it is.
                case "m_20077_": injectCancelVoid(m);   break;

                // ── NEW: negative potion effects — cancel before they apply ──
                // addEffect() returns boolean; returning false means "rejected".
                // We only block it when god mode is on so normal potions
                // still work if you toggle god mode off.
                case "m_7925_": injectCancelNegativeEffect(m); break;

                // ── NEW: fire / lava tick damage ─────────────────────────────
                // setRemainingFireTicks sends the entity on fire; void cancel stops it.
                case "m_20014_": injectCancelVoid(m);   break;
            }
        }

        // Use COMPUTE_MAXS so ASM recalculates stack depth after our injections.
        // DO NOT use COMPUTE_FRAMES here — it breaks Mixin-loaded classes that
        // haven't gone through remapping yet.
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cn.accept(cw);
        return cw.toByteArray();
    }

    // ── Injection helpers ─────────────────────────────────────────────────────

    // Returns false (boolean) early if god mode is on.
    // Used for: hurt() — false means "damage was blocked"
    static void injectCancelBoolean(MethodNode m) {
        InsnList insn = new InsnList();
        LabelNode skip = new LabelNode();

        insn.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insn.add(new MethodInsnNode(Opcodes.INVOKESTATIC, HELPER, "isGod",
                "(Lnet/minecraft/world/entity/LivingEntity;)Z", false));
        insn.add(new JumpInsnNode(Opcodes.IFEQ, skip)); // if NOT god → skip
        insn.add(new InsnNode(Opcodes.ICONST_0));        // push false
        insn.add(new InsnNode(Opcodes.IRETURN));         // return false
        insn.add(skip);                                  // ← normal code resumes here

        m.instructions.insert(insn);
    }

    // Returns void early if god mode is on.
    // Used for: die(), knockback(), kill(), fire ticks, actuallyHurt()
    static void injectCancelVoid(MethodNode m) {
        InsnList insn = new InsnList();
        LabelNode skip = new LabelNode();

        insn.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insn.add(new MethodInsnNode(Opcodes.INVOKESTATIC, HELPER, "isGod",
                "(Lnet/minecraft/world/entity/LivingEntity;)Z", false));
        insn.add(new JumpInsnNode(Opcodes.IFEQ, skip));
        insn.add(new InsnNode(Opcodes.RETURN));
        insn.add(skip);

        m.instructions.insert(insn);
    }

    // Restores health and returns early — used for die() specifically
    // so health snaps back instead of the entity freezing at 0
    static void injectDiePatch(MethodNode m) {
        InsnList insn = new InsnList();
        LabelNode skip = new LabelNode();

        insn.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insn.add(new MethodInsnNode(Opcodes.INVOKESTATIC, HELPER, "isGod",
                "(Lnet/minecraft/world/entity/LivingEntity;)Z", false));
        insn.add(new JumpInsnNode(Opcodes.IFEQ, skip));

        // Call your helper to snap health back to max
        insn.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insn.add(new MethodInsnNode(Opcodes.INVOKESTATIC, HELPER, "restoreHealth",
                "(Lnet/minecraft/world/entity/LivingEntity;)V", false));

        insn.add(new InsnNode(Opcodes.RETURN));
        insn.add(skip);

        m.instructions.insert(insn);
    }

    // Forces isDeadOrDying() to return false — prevents death screen,
    // loot drops, respawn logic even if health briefly hits 0
    static void injectIsDead(MethodNode m) {
        InsnList insn = new InsnList();
        LabelNode skip = new LabelNode();

        insn.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insn.add(new MethodInsnNode(Opcodes.INVOKESTATIC, HELPER, "isGod",
                "(Lnet/minecraft/world/entity/LivingEntity;)Z", false));
        insn.add(new JumpInsnNode(Opcodes.IFEQ, skip));
        insn.add(new InsnNode(Opcodes.ICONST_0)); // false = "not dead"
        insn.add(new InsnNode(Opcodes.IRETURN));
        insn.add(skip);

        m.instructions.insert(insn);
    }

    // NEW: Cancel addEffect() for negative/harmful potion effects only.
    // addEffect() takes a MobEffectInstance as arg1 — we delegate the
    // "is this harmful?" check to your helper so the logic stays in Java,
    // not buried in bytecode.
    static void injectCancelNegativeEffect(MethodNode m) {
        InsnList insn = new InsnList();
        LabelNode skip = new LabelNode();

        insn.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insn.add(new MethodInsnNode(Opcodes.INVOKESTATIC, HELPER, "isGod",
                "(Lnet/minecraft/world/entity/LivingEntity;)Z", false));
        insn.add(new JumpInsnNode(Opcodes.IFEQ, skip)); // not god → let it through

        // Pass the MobEffectInstance (arg1) to helper to check if it's harmful
        insn.add(new VarInsnNode(Opcodes.ALOAD, 1));
        insn.add(new MethodInsnNode(Opcodes.INVOKESTATIC, HELPER, "isHarmfulEffect",
                "(Lnet/minecraft/world/effect/MobEffectInstance;)Z", false));
        insn.add(new JumpInsnNode(Opcodes.IFEQ, skip)); // not harmful → let it through

        // It IS harmful and god mode IS on → reject the effect
        insn.add(new InsnNode(Opcodes.ICONST_0)); // return false = "effect rejected"
        insn.add(new InsnNode(Opcodes.IRETURN));
        insn.add(skip);

        m.instructions.insert(insn);
    }
}