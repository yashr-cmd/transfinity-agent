package agent;

// ============================================================
//  AgentMain.java  —  Transfinity Defense System (single file)
//  Requires: ASM9 on classpath (asm-9.x.jar + asm-commons-9.x.jar)
// ============================================================

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

public class AgentMain {

    // ── ASM API version we target ────────────────────────────────────────────
    private static final int ASM_API = Opcodes.ASM9;

    // ── Threat score added for each suspicious class seen ────────────────────
    private static final int THREAT_PER_HIT = 2;

    // ── At this score the group gets DISABLED (methods wiped) ────────────────
    private static final int DISABLE_THRESHOLD = 4;

    // ── ABOVE this score the group gets ERASED (empty shell class) ───────────
    private static final int ERASE_THRESHOLD = 6;

    // ========================================================================
    //  premain — JVM calls this before your actual main() runs
    // ========================================================================
    public static void premain(String args, Instrumentation inst) {
        banner("TRANSFINITY DEFENSE LOADED — WATCHING ALL CLASS LOADS");
        inst.addTransformer(new DefenseTransformer());
    }

    // ========================================================================
    //  DefenseTransformer — intercepts every class the JVM loads
    // ========================================================================
    public static class DefenseTransformer implements ClassFileTransformer {

        // Tracks cumulative threat score per package-group
        // e.g. "com/evil" is the group for "com/evil/MyPlugin" and "com/evil/MyXformer"
        private final ConcurrentHashMap<String, AtomicInteger> groupScores =
                new ConcurrentHashMap<>();

        // Stores the highest verdict already decided for each group.
        // Once a group is marked ERASE it can NEVER go back to DISABLE or ALLOW.
        private final ConcurrentHashMap<String, Action> groupVerdict =
                new ConcurrentHashMap<>();

        // ── The three things we can do to a class ────────────────────────────
        enum Action { ALLOW, DISABLE, ERASE }

        // --------------------------------------------------------------------
        //  transform() — called by the JVM for EVERY class, before it executes
        // --------------------------------------------------------------------
        @Override
        public byte[] transform(
                Module module,
                ClassLoader loader,
                String className,           // e.g. "com/evil/MyPlugin"  (slashes, not dots)
                Class<?> classBeingRedefined,
                ProtectionDomain domain,
                byte[] classfileBuffer) {   // raw bytecode of the class

            if (className == null) return null;

            // ── GLOBAL WHITELIST ──
            // 🛑 HARD IMMUNITY (DO NOT TOUCH EVER)
            if (className.startsWith("org/spongepowered/")
                    || className.startsWith("cpw/mods/")
                    || className.startsWith("net/minecraftforge/")
                    || className.startsWith("net/neoforged/")
                    || className.startsWith("java/")
                    || className.startsWith("javax/")
                    || className.startsWith("jdk/")
                    || className.startsWith("sun/")
                    || className.startsWith("org/objectweb/")
                    || className.startsWith("net/minecraft/")
                    || className.startsWith("com/mojang/")
                    || className.startsWith("io/netty/")
                    || className.startsWith("org/apache/")
                    || className.startsWith("com/google/")) {
                return null;
            }

            // ── WHITELIST: classes we patch ourselves; skip the threat system ──
            if (className.equals("net/minecraft/world/entity/LivingEntity")) {
                log("GOD-MODE", "Injecting god mode into LivingEntity");
                return patchLivingEntity(classfileBuffer);
            }

            // ── STEP 1: Check if this class looks suspicious ──────────────────
            String reason = evaluateSuspicion(className);

            // Nothing suspicious → leave it alone
            if (reason == null) return null;

            // ── STEP 2: Extra-loud alert specifically for Mixin classes ────────
            if (reason.equals("mixin")) {
                loudMixinAlert(className);
            }

            // ── STEP 3: Add threat to this class's package group ───────────────
            String group    = extractGroup(className);
            int    newScore = addThreat(group);

            // ── STEP 4: Decide what to do based on the group's total score ─────
            Action action = resolveAction(group, newScore);

            // ── STEP 5: Execute the action ─────────────────────────────────────
            switch (action) {

                case ERASE: {
                    // Score is WAY too high — nuke the entire class into a hollow shell
                    loudAction("✖✖✖  E R A S E", className, reason, group, newScore);
                    return emptyClass(classfileBuffer);
                }

                case DISABLE: {
                    // Score is over threshold — wipe all method bodies
                    loudAction("⚠⚠  D I S A B L E", className, reason, group, newScore);

                    // Special case: MyLib2 has a targeted patch; everything else gets full wipe
                    if (className.contains("MyLib2")) {
                        return disableMyLib2(classfileBuffer);
                    }
                    return disableAllMethods(classfileBuffer);
                }

                default: {
                    // ALLOW — suspicious but score not high enough to act yet; log & watch
                    log("WATCH", String.format(
                            "%-55s | reason=%-22s | group=%-20s | groupScore=%d",
                            className, reason, group, newScore));
                    return null;   // return null = "don't change the bytecode"
                }
            }
        }

        // --------------------------------------------------------------------
        //  Suspicion rules — returns a reason string, or null if class is clean
        // --------------------------------------------------------------------
        private static String evaluateSuspicion(String className) {
            // Check for Mixin annotations / packages first (gets its own loud alert)
            if (className.contains("Mixin")
                    || className.startsWith("org/spongepowered/asm")
                    || className.startsWith("org/spongepowered/mixin")) {
                return "mixin";
            }

            // Known bad library
            if (className.contains("MyLib2"))       return "known-bad-lib";

            // Explicit transformer / plugin class names
            if (className.contains("MyPlugin"))     return "plugin-transformer";
            if (className.contains("MyXformer"))    return "explicit-transformer";

            // Generic suspicious naming patterns
            if (className.contains("Transformer"))  return "transformer-name";
            if (className.contains("ClassVisitor")) return "asm-visitor";
            if (className.contains("MethodVisitor"))return "asm-method-visitor";
            if (className.contains("ByteBuddy"))    return "bytebuddy-agent";
            if (className.contains("javassist"))    return "javassist-agent";

            // Any class that is itself an Agent is suspicious
            if (className.contains("Agent")
                    && !className.startsWith("agent/"))  // don't flag ourselves
                return "agent-class";

            // Instrumentation hooks
            if (className.contains("Instrumentation")) return "instrumentation-hook";

            return null;   // clean
        }

        // --------------------------------------------------------------------
        //  Group threat accounting
        // --------------------------------------------------------------------

        // Extracts the package group: first two segments of the class path.
        // "com/evil/plugin/Foo" → "com/evil"
        // This makes ALL classes from the same package share one threat score.
        private static String extractGroup(String className) {
            String[] parts = className.split("/");
            if (parts.length >= 2) return parts[0] + "/" + parts[1];
            return parts[0];
        }

        // Adds THREAT_PER_HIT to the group and returns the new total score
        private int addThreat(String group) {
            AtomicInteger score = groupScores.computeIfAbsent(
                    group, k -> new AtomicInteger(0));
            int newScore = score.addAndGet(THREAT_PER_HIT);
            log("THREAT", String.format("Group %-30s | +%d → total score %d",
                    group, THREAT_PER_HIT, newScore));
            return newScore;
        }

        // Decides (and remembers) the action for a group given its current score.
        // The stored verdict can only ESCALATE — it never goes down.
        private Action resolveAction(String group, int score) {
            Action fresh;
            if      (score > ERASE_THRESHOLD)    fresh = Action.ERASE;
            else if (score >= DISABLE_THRESHOLD) fresh = Action.DISABLE;
            else                                 fresh = Action.ALLOW;

            // merge: keep whichever is higher (ordinal order: ALLOW < DISABLE < ERASE)
            groupVerdict.merge(group, fresh, (existing, incoming) ->
                    incoming.ordinal() > existing.ordinal() ? incoming : existing);

            return groupVerdict.get(group);
        }
    }

    // ========================================================================
    //  Bytecode patch utilities
    // ========================================================================

    // ── ERASE: return a class that exists but does absolutely nothing ─────────
    // Keeps only the constructor (calls super()) so the JVM doesn't crash.
    // Every other method is completely removed.
    private static byte[] emptyClass(byte[] original) {
        ClassReader cr = new ClassReader(original);
        ClassWriter cw = new ClassWriter(0);

        cr.accept(new ClassVisitor(ASM_API, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String desc,
                                             String sig, String[] exceptions) {
                // Keep constructor shell so the class is still instantiatable
                if (name.equals("<init>")) {
                    MethodVisitor mv = super.visitMethod(access, name, desc, sig, exceptions);
                    mv.visitCode();
                    mv.visitVarInsn(Opcodes.ALOAD, 0);
                    mv.visitMethodInsn(Opcodes.INVOKESPECIAL,
                            "java/lang/Object", "<init>", "()V", false);
                    mv.visitInsn(Opcodes.RETURN);
                    mv.visitMaxs(1, 1);
                    mv.visitEnd();
                    return null;   // returning null means "don't forward original body"
                }
                // Drop every other method (static init, all public methods, etc.)
                return null;
            }
        }, 0);

        return cw.toByteArray();
    }

    // ── DISABLE (generic): replace every method body with an immediate RETURN ──
    // The method still exists so interfaces are satisfied, but it does nothing.
    // Return value is zeroed / null depending on the return type.
    private static byte[] disableAllMethods(byte[] original) {
        ClassReader cr = new ClassReader(original);
        // COMPUTE_FRAMES → ASM recalculates stack maps so we don't get VerifyError
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);

        cr.accept(new ClassVisitor(ASM_API, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String desc,
                                             String sig, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, desc, sig, exceptions);

                // Leave constructors and static initializers intact —
                // touching them tends to break class loading entirely.
                if (name.equals("<init>") || name.equals("<clinit>")) return mv;

                // For every other method: wrap with a visitor that
                // IGNORES all original instructions and emits only a return.
                return new MethodVisitor(ASM_API, mv) {

                    @Override
                    public void visitCode() {
                        super.visitCode();

                        // Emit the correct zero / null return for each return type
                        Type returnType = Type.getReturnType(desc);
                        switch (returnType.getSort()) {
                            case Type.VOID:
                                mv.visitInsn(Opcodes.RETURN);    break;
                            case Type.BOOLEAN:
                            case Type.INT:
                            case Type.BYTE:
                            case Type.CHAR:
                            case Type.SHORT:
                                mv.visitInsn(Opcodes.ICONST_0);
                                mv.visitInsn(Opcodes.IRETURN);   break;
                            case Type.LONG:
                                mv.visitInsn(Opcodes.LCONST_0);
                                mv.visitInsn(Opcodes.LRETURN);   break;
                            case Type.FLOAT:
                                mv.visitInsn(Opcodes.FCONST_0);
                                mv.visitInsn(Opcodes.FRETURN);   break;
                            case Type.DOUBLE:
                                mv.visitInsn(Opcodes.DCONST_0);
                                mv.visitInsn(Opcodes.DRETURN);   break;
                            default:  // object / array
                                mv.visitInsn(Opcodes.ACONST_NULL);
                                mv.visitInsn(Opcodes.ARETURN);   break;
                        }
                        mv.visitMaxs(2, 1);
                        mv.visitEnd();
                    }

                    // ── Drop all original bytecode instructions ───────────────
                    @Override public void visitInsn(int op)                          {}
                    @Override public void visitVarInsn(int op, int v)               {}
                    @Override public void visitMethodInsn(int op, String o,
                                                          String n, String d, boolean i)          {}
                    @Override public void visitFieldInsn(int op, String o,
                                                         String n, String d)                     {}
                    @Override public void visitJumpInsn(int op, Label l)            {}
                    @Override public void visitLabel(Label l)                       {}
                    @Override public void visitMaxs(int s, int l)                   {}
                    @Override public void visitTypeInsn(int op, String type)        {}
                    @Override public void visitLdcInsn(Object cst)                  {}
                    @Override public void visitIntInsn(int op, int operand)         {}
                    @Override public void visitIincInsn(int v, int inc)             {}
                };
            }
        }, ClassReader.EXPAND_FRAMES);

        return cw.toByteArray();
    }

    // ── DISABLE (targeted): MyLib2-specific patch ─────────────────────────────
    // Falls back to full method wipe — replace with your own ASM logic if needed.
    private static byte[] disableMyLib2(byte[] classfileBuffer) {
        // TODO: add MyLib2-specific targeted patching logic here if you have it.
        // For now we just wipe all methods the same as the generic path.
        return disableAllMethods(classfileBuffer);
    }

    // ── WHITELIST patch: inject god mode into LivingEntity ───────────────────
    private static byte[] patchLivingEntity(byte[] classfileBuffer) {
        // TODO: plug in your existing god-mode ASM patch here.
        // Returning unchanged bytes for now so the game still boots.
        return classfileBuffer;
    }

    // ========================================================================
    //  Logging helpers
    // ========================================================================

    // Standard tagged log line
    private static void log(String tag, String msg) {
        System.out.printf("[AGENT | %-18s] %s%n", tag, msg);
    }

    // Big banner for startup
    private static void banner(String msg) {
        String bar = "═".repeat(60);
        System.out.println("\n╔" + bar + "╗");
        System.out.printf( "║  %-58s  ║%n", msg);
        System.out.println("╚" + bar + "╝\n");
    }

    // Loud action line (disable / erase)
    private static void loudAction(String action, String className,
                                   String reason, String group, int score) {
        String bar = "!".repeat(70);
        System.out.println(bar);
        System.out.printf("[AGENT] %s%n", action);
        System.out.printf("        class  : %s%n", className);
        System.out.printf("        reason : %s%n", reason);
        System.out.printf("        group  : %s%n", group);
        System.out.printf("        score  : %d%n", score);
        System.out.println(bar);
    }

    // !! Extra-loud alert specifically for Mixin classes !!
    private static void loudMixinAlert(String className) {
        String bar = "*".repeat(70);
        System.out.println("\n" + bar);
        System.out.println("*                  !! MIXIN DETECTED !!                           *");
        System.out.println("*                  !! MIXIN DETECTED !!                           *");
        System.out.println("*                  !! MIXIN DETECTED !!                           *");
        System.out.printf( "*  CLASS: %-59s  *%n", className);
        System.out.println("*  Threat points being added to package group NOW.                *");
        System.out.println(bar + "\n");
    }
}