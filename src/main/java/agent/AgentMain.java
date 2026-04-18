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
    //    Raised from 4 → 6
    private static final int DISABLE_THRESHOLD = 6;

    // ── ABOVE this score the group gets ERASED (empty shell class) ───────────
    //    Raised from 6 → 8
    private static final int ERASE_THRESHOLD = 8;

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

        private static boolean isCoremodEntry(byte[] bytes) {
            try {
                ClassReader cr = new ClassReader(bytes);
                final boolean[] found = {false};

                cr.accept(new ClassVisitor(ASM_API) {
                    @Override
                    public void visit(int v, int a, String n, String sig,
                                      String superName, String[] interfaces) {

                        if (interfaces != null) {
                            for (String i : interfaces) {
                                if (i.contains("ITransformationService")
                                        || i.contains("ILaunchPluginService")) {
                                    found[0] = true;
                                }
                            }
                        }
                    }
                }, 0);

                return found[0];

            } catch (Throwable t) {
                return false;
            }
        }

        private static int detectRuntimeThreat(byte[] bytes) {
            try {
                ClassReader cr = new ClassReader(bytes);
                final int[] flags = {0};

                cr.accept(new ClassVisitor(ASM_API) {
                    @Override
                    public MethodVisitor visitMethod(int access, String name, String desc,
                                                     String sig, String[] exceptions) {
                        return new MethodVisitor(ASM_API) {
                            @Override
                            public void visitMethodInsn(int op, String owner,
                                                        String name, String desc, boolean itf) {

                                // flag 1 — VirtualMachine attach/loadAgent (runtime agent injection)
                                if (owner.contains("VirtualMachine")
                                        && (name.equals("attach") || name.equals("loadAgent")))
                                    flags[0] |= 1;

                                // flag 2 — Instrumentation addTransformer/retransformClasses (runtime retransform)
                                if (owner.contains("Instrumentation")
                                        && (name.contains("addTransformer")
                                        || name.contains("retransformClasses")))
                                    flags[0] |= 2;

                                // flag 4 — System/Runtime load/loadLibrary (DLL injection)
                                if ((owner.equals("java/lang/System") || owner.equals("java/lang/Runtime"))
                                        && (name.equals("load") || name.equals("loadLibrary")))
                                    flags[0] |= 4;

                                // flag 8 — Unsafe / defineClass (suspicious but not instant-kill)
                                if (owner.contains("Unsafe") || name.equals("defineClass"))
                                    flags[0] |= 8;
                            }
                        };
                    }
                }, 0);

                return flags[0];

            } catch (Throwable t) {
                return 0;
            }
        }

        private static boolean isRealTransformer(byte[] bytes) {
            try {
                ClassReader cr = new ClassReader(bytes);
                final boolean[] found = {false};

                cr.accept(new ClassVisitor(ASM_API) {
                    @Override
                    public void visit(int v, int a, String n, String sig,
                                      String superName, String[] interfaces) {

                        if (interfaces != null) {
                            for (String i : interfaces) {
                                // Only match EXACT coremod transformer interfaces
                                if (i.equals("cpw/mods/modlauncher/api/ITransformationService")
                                        || i.equals("cpw/mods/modlauncher/api/ITransformer")
                                        || i.equals("java/lang/instrument/ClassFileTransformer")) {
                                    found[0] = true;
                                }
                            }
                        }
                    }
                }, 0);

                return found[0];
            } catch (Throwable t) { return false; }
        }

        private static boolean isASMManipulator(byte[] bytes) {
            try {
                ClassReader cr = new ClassReader(bytes);
                final boolean[] found = {false};

                cr.accept(new ClassVisitor(ASM_API) {
                    @Override
                    public void visit(int v, int a, String n, String sig,
                                      String superName, String[] interfaces) {

                        if (superName != null && superName.contains("ClassVisitor"))
                            found[0] = true;

                        if (superName != null && superName.contains("MethodVisitor"))
                            found[0] = true;
                    }

                    @Override
                    public MethodVisitor visitMethod(int access, String name, String desc,
                                                     String sig, String[] exceptions) {

                        return new MethodVisitor(ASM_API) {
                            @Override
                            public void visitMethodInsn(int op, String owner,
                                                        String name, String desc, boolean itf) {

                                if (owner.startsWith("org/objectweb/asm")) {
                                    found[0] = true;
                                }
                            }
                        };
                    }
                }, 0);

                return found[0];

            } catch (Throwable t) {
                return false;
            }
        }

        private static boolean hasMixinInjection(byte[] bytes) {
            try {
                ClassReader cr = new ClassReader(bytes);
                final boolean[] found = {false};

                cr.accept(new ClassVisitor(ASM_API) {
                    @Override
                    public MethodVisitor visitMethod(int access, String name, String desc,
                                                     String sig, String[] exceptions) {
                        return new MethodVisitor(ASM_API) {
                            @Override
                            public void visitMethodInsn(int opcode, String owner,
                                                        String name, String desc, boolean itf) {
                                // Only flag ACTUAL mixin injection API calls
                                if (owner.equals("org/spongepowered/asm/mixin/injection/callback/CallbackInfo")
                                        || owner.equals("org/spongepowered/asm/mixin/injection/Inject")) {
                                    found[0] = true;
                                }
                            }
                        };
                    }
                }, 0);

                return found[0];
            } catch (Throwable t) { return false; }
        }

        private static boolean isTransformService(byte[] bytes) {
            try {
                ClassReader cr = new ClassReader(bytes);
                final boolean[] found = {false};

                cr.accept(new ClassVisitor(ASM_API) {
                    @Override
                    public void visit(int v, int a, String n, String sig,
                                      String superName, String[] interfaces) {

                        if (interfaces != null) {
                            for (String i : interfaces) {
                                if (i.contains("TransformationService")) {
                                    found[0] = true;
                                }
                            }
                        }
                    }
                }, 0);

                return found[0];

            } catch (Throwable t) {
                return false;
            }
        }

        // Tracks cumulative threat score per package-group
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
                String className,
                Class<?> classBeingRedefined,
                ProtectionDomain domain,
                byte[] classfileBuffer) {

            if (className == null) return null;

            // ── OmniMobs — INTENTIONALLY NOT WHITELISTED ──
            // flashfur/omnimobs/ — caught attempting runtime agent injection
            // via CoreModMain.loadAgentAndTransformClasses()

            // ── GLOBAL WHITELIST ──
            // 🛑 HARD IMMUNITY (DO NOT TOUCH EVER)
            if (
                // ── CORE / JVM / JDK ──
                    className.startsWith("java/")
                            || className.startsWith("javax/")
                            || className.startsWith("jdk/")
                            || className.startsWith("sun/")
                            || className.startsWith("jdk/internal/")
                            || className.startsWith("jdk/jfr/")
                            || className.startsWith("org/openjdk/")

                            // ── ASM / BYTECODE / INSTRUMENTATION ──
                            || className.startsWith("org/objectweb/asm/")
                            || className.startsWith("org/objectweb/")
                            || className.startsWith("groovyjarjarasm/asm/ClassWriter")
                            || className.startsWith("groovyjarjarasm/asm/")
                            || className.startsWith("groovyjarjarasm/")
                            || className.startsWith("java/lang/instrument/")
                            || className.startsWith("sun/instrument/")

                            // ── GROOVY / KOTLIN / SCRIPTING ──
                            || className.startsWith("groovy/")
                            || className.startsWith("org/codehaus/groovy/")
                            || className.startsWith("kotlin/")

                            // ── GRADLE / BUILD TOOLS ──
                            || className.startsWith("org/gradle/")
                            || className.startsWith("net/rubygrapefruit/")

                            // ── MINECRAFT CORE ──
                            || className.startsWith("net/minecraft/")
                            || className.startsWith("com/mojang/")

                            // ── FORGE / NEOFORGE / CPW ──
                            || className.startsWith("net/minecraftforge/")
                            || className.startsWith("net/neoforged/")
                            || className.startsWith("cpw/mods/")

                            // ── MCREATOR / TRANSFINITY ──
                            || className.startsWith("net/mcreator/transfinityimproved/")
                            || className.startsWith("net/mcreator/transfinityimproved/coremod/")
                            || className.startsWith("net/mcreator/transfinityimproved/runtime/")
                            || className.startsWith("runtime/")

                            // ── COMMON LIBRARIES ──
                            || className.startsWith("io/netty/")
                            || className.startsWith("org/apache/")
                            || className.startsWith("com/google/")
                            || className.startsWith("net/jodah/")
                            || className.startsWith("org/joml/")
                            || className.startsWith("org/lwjgl/")

                            // ════════════════════════════════════════════════
                            // ── PERFORMANCE MODS ──
                            // ════════════════════════════════════════════════

                            || className.startsWith("net/dmodoomsirius/")
                            || className.startsWith("com/godzillaspinofossil/")
                            || className.startsWith("godzillaspinofossil/")
                            || className.startsWith("com/fossil/")
                            || className.startsWith("prehistoric/")
                            || className.startsWith("com/prehistoric/")
                            || className.startsWith("net/nonamecrackers2/")
                            || className.startsWith("nonamecrackers2/")

                            // ── PekHUI (HUD mod) ──
                            || className.startsWith("squeek502/pekhui/")
                            || className.startsWith("squeek502/")

                            // ── AppleSkin ──
                            || className.startsWith("squeek502/appleskin/")

                            // ── Xaero's (minimap / worldmap) ──
                            || className.startsWith("xaero/")

                            // ── JourneyMap ──
                            || className.startsWith("journeymap/")

                            // ── Just Enough Items (mezz) ──
                            || className.startsWith("mezz/")

                            // ── KubeJS / Rhino scripting ──
                            || className.startsWith("dev/latvian/mods/")
                            || className.startsWith("dev/latvian/")

                            // ── FTB mods ──
                            || className.startsWith("com/feed_the_beast/")
                            || className.startsWith("dev/ftb/")

                            // ── Quark / AutoRegLib (Vazkii continued) ──
                            || className.startsWith("org/violetmoon/")

                            // ── Configured (MrCrayfish) ──
                            || className.startsWith("com/mrcrayfish/configured/")

                            // ── FLAN's mod ──
                            || className.startsWith("com/flansmod/")

                            // ── TerraForged ──
                            || className.startsWith("com/terraforged/")

                            // ── Create mod ──
                            || className.startsWith("com/simibubi/create/")
                            || className.startsWith("com/simibubi/")

                            // ── Flywheel (Create dep) ──
                            || className.startsWith("com/jozufozu/flywheel/")
                            || className.startsWith("com/jozufozu/")

                            // ── Registrate (Create dep) ──
                            || className.startsWith("com/tterrag/registrate/")
                            || className.startsWith("com/tterrag/")

                            // ── Patchouli (book API) ──
                            || className.startsWith("vazkii/patchouli/")
                            || className.startsWith("vazkii/")

                            // ── Botania / Quark / AutoRegLib ──
                            || className.startsWith("net/darkhax/")
                            || className.startsWith("net/darkhax/bookshelf/")
                            || className.startsWith("net/darkhax/gamestages/")

                            // ── Curios API ──
                            || className.startsWith("top/theillusivec4/curios/")
                            || className.startsWith("top/theillusivec4/")

                            // ── Configured / Catalogue ──
                            || className.startsWith("com/mrcrayfish/")

                            // ── Cloth Config / ModMenu ──
                            || className.startsWith("me/shedaniel/clothconfig/")
                            || className.startsWith("me/shedaniel/")

                            // ── Architectury API ──
                            || className.startsWith("dev/architectury/")

                            // ── Fabric API / Loader ──
                            || className.startsWith("net/fabricmc/")
                            || className.startsWith("net/fabricmc/fabric/")
                            || className.startsWith("net/fabricmc/loader/")

                            // ── Forge Config API Port ──
                            || className.startsWith("fuzs/forgeconfigapiport/")
                            || className.startsWith("fuzs/")

                            // ── Mantle (Tinkers dep) ──
                            || className.startsWith("slimeknights/mantle/")
                            || className.startsWith("slimeknights/")

                            // ── Caelus API ──
                            || className.startsWith("top/theillusivec4/caelus/")

                            // ── JEI / REI / EMI (recipe viewers) ──
                            || className.startsWith("mezz/jei/")
                            || className.startsWith("me/shedaniel/rei/")
                            || className.startsWith("dev/emi/")

                            // ── Jade / HWYLA / TOP ──
                            || className.startsWith("snownee/jade/")
                            || className.startsWith("mcp/mobius/waila/")
                            || className.startsWith("mcjty/theoneprobe/")

                            // ── YACL (Yet Another Config Lib) ──
                            || className.startsWith("dev/isxander/yacl/")
                            || className.startsWith("dev/isxander/")

                            // ── CreativeCore ──
                            || className.startsWith("team/creative/")

                            // ── Moonlight Lib ──
                            || className.startsWith("net/mehvahdjukaar/moonlight/")
                            || className.startsWith("net/mehvahdjukaar/")

                            // ── Blueprint (team abnormals) ──
                            || className.startsWith("com/teamabnormals/blueprint/")
                            || className.startsWith("com/teamabnormals/")

                            // ── Placebo (Shadows of Gregory dep) ──
                            || className.startsWith("shadows/placebo/")

                            // ── TerraBlender ──
                            || className.startsWith("terrablender/")

                            // ── Night Config ──
                            || className.startsWith("com/electronwill/nightconfig/")
                            || className.startsWith("com/electronwill/")

                            // ── GSON / Jackson / common serializers ──
                            || className.startsWith("com/fasterxml/jackson/")

                            // ── GeckoLib (animation library used by hundreds of mods) ──
                            || className.startsWith("software/bernie/geckolib/")
                            || className.startsWith("software/bernie/")

                            // ── Geckolib dependencies / related ──
                            || className.startsWith("com/eliotlash/mclib/")
                            || className.startsWith("com/eliotlash/")

                            // ── Sodium / Lithium / Phosphor (jellysquid3) ──
                            || className.startsWith("me/jellysquid/")

                            // ── Sodium (CaffeineMC fork/org) ──
                            || className.startsWith("net/caffeinemc/")

                            // ── Iris Shaders ──
                            || className.startsWith("net/irisshaders/")
                            || className.startsWith("net/coderbot/iris/")
                            || className.startsWith("net/coderbot/")

                            // ── Oculus (Forge Iris port) ──
                            || className.startsWith("net/coderbot/oculus/")

                            // ── Starlight (chunk lighting engine) ──
                            || className.startsWith("ca/spottedleaf/")

                            // ── FerriteCore (memory optimization) ──
                            || className.startsWith("malte0811/")

                            // ── Embeddium (Sodium Forge fork) ──
                            || className.startsWith("org/embeddedt/embeddium/")

                            // ── ModernFix (startup / memory / misc fixes) ──
                            || className.startsWith("org/embeddedt/modernfix/")

                            // ── Krypton (networking optimization) ──
                            || className.startsWith("me/astei/krypton/")
                            || className.startsWith("me/astei/")

                            // ── Smooth Boot (thread optimization) ──
                            || className.startsWith("me/lortseam/smoothboot/")
                            || className.startsWith("me/lortseam/")

                            // ── ImmediatelyFast (render batching) ──
                            || className.startsWith("net/raphimc/immediatelyfast/")
                            || className.startsWith("net/raphimc/")

                            // ── VulkanMod ──
                            || className.startsWith("net/vulkanmod/")

                            // ── Nvidium / Cortex ──
                            || className.startsWith("me/cortex/nvidium/")
                            || className.startsWith("me/cortex/")

                            // ── C2ME (Concurrent Chunk Management Engine) ──
                            || className.startsWith("com/ishland/c2me/")
                            || className.startsWith("com/ishland/")

                            // ── OptiFine ──
                            || className.startsWith("optifine/")
                            || className.startsWith("net/optifine/")

                            // ── OptiFabric ──
                            || className.startsWith("me/modmuss50/optifabric/")
                            || className.startsWith("me/modmuss50/")

                            // ── FalsePattern ──
                            || className.startsWith("com/falsepattern/")

                            // ── Clumps (XP orb merging) ──
                            || className.startsWith("com/jaredlll08/clumps/")
                            || className.startsWith("com/jaredlll08/")

                            // ── FastWorkbench / FastFurnace / FastSuite (shadows) ──
                            || className.startsWith("shadows/fastbench/")
                            || className.startsWith("shadows/fastfurnace/")
                            || className.startsWith("shadows/fastsuite/")
                            || className.startsWith("shadows/")

                            // ── Chunky (pre-generation) ──
                            || className.startsWith("org/popcraft/chunky/")
                            || className.startsWith("org/popcraft/")

                            // ── BetterFps ──
                            || className.startsWith("guichaguri/betterfps/")
                            || className.startsWith("guichaguri/")

                            // ── LazyDFU (deferred DFU init) ──
                            || className.startsWith("com/tuxedocat/lazydfu/")
                            || className.startsWith("me/lambdaurora/lazydfu/")

                            // ── Entity Culling (tr7zw) ──
                            || className.startsWith("mcp/mobius/xtones/")
                            || className.startsWith("net/tr7zw/")

                            // ── Exordium (GUI render throttling) ──
                            || className.startsWith("com/github/terminalmc/exordium/")

                            // ── Alternate Current (redstone engine) ──
                            || className.startsWith("alternate_current/")
                            || className.startsWith("com/thealgorithm476/alternatecurrent/")

                            // ── Concurrent-util / Vanilla Scheduling ──
                            || className.startsWith("ca/spottedleaf/concurrentutil/")

                            // ── Spark (profiler) ──
                            || className.startsWith("me/lucko/spark/")

                            // ── ServerCore ──
                            || className.startsWith("com/github/servercore/")

                            // ── Carpet Mod (technical/perf) ──
                            || className.startsWith("carpet/")

                            // ── Patchwork / Sponge ──
                            || className.startsWith("org/spongepowered/")

                            // ── SpongeForge / SpongeAPI ──
                            || className.startsWith("org/spongepowered/asm/")

                            // ── MixinExtras ──
                            || className.startsWith("com/llamalad7/mixinextras/")
                            || className.startsWith("com/llamalad7/")

                            // ── Dynamic FPS ──
                            || className.startsWith("dynamic_fps/")
                            || className.startsWith("net/lasertag/dynamicfps/")

                            // ── Cull Leaves / Cull Particles ──
                            || className.startsWith("net/draycia/")
                            || className.startsWith("com/github/xt9/cullparticles/")

                            // ── MemoryLeakFix ──
                            || className.startsWith("com/github/fudge/memoryleakfix/")

                            // ── AttributeFix ──
                            || className.startsWith("com/jamieswhiteshirt/attributefix/")
                            || className.startsWith("com/jamieswhiteshirt/")

                            // ── Radium (Lithium Forge port by Frozenblock) ──
                            || className.startsWith("org/frozenblock/")

            ) {
                return null;
            }

            // ── WHITELIST: classes we patch ourselves; skip the threat system ──
            if (className.equals("net/minecraft/world/entity/LivingEntity")) {
                log("GOD-MODE", "Injecting god mode into LivingEntity");
                return PatchUtils.patchLivingEntity(classfileBuffer);
            }

            // ── JDK INTERNAL IMMUNITY ─────────────────────────────
            if (className.startsWith("com/sun/")
                    || className.startsWith("sun/")
                    || className.startsWith("jdk/")
                    || className.startsWith("java/lang/management/")) {
                return null;
            }

            // ════════════════════════════════════════════════════════════════
            //  RUNTIME INJECTION CHECK — INSTANT KILL, NO SCORE NEEDED
            //
            //  flags 1, 2, 4 = VirtualMachine.attach/loadAgent,
            //  Instrumentation.addTransformer/retransformClasses,
            //  System/Runtime.load/loadLibrary (DLL injection)
            //
            //  These are hard kills regardless of package or score.
            //  flag 8 (Unsafe/defineClass) still goes through score system.
            // ════════════════════════════════════════════════════════════════
            int runtime = detectRuntimeThreat(classfileBuffer);

            if (runtime != 0 && !className.startsWith("org/gradle/")) {

                if ((runtime & 7) != 0) {
                    // flags 1 | 2 | 4 — runtime agent or DLL injection → instant erase
                    String group = extractGroup(className);
                    int score = addThreat(group);
                    loudAction("✖✖✖ INSTANT KILL (RUNTIME AGENT/DLL INJECTION)",
                            className, "agent/dll/retransform", group, score);
                    return emptyClass(classfileBuffer);
                }

                if ((runtime & 8) != 0) {
                    // flag 8 — Unsafe/defineClass → score-gated disable (not instant kill)
                    String group = extractGroup(className);
                    int score = addThreat(group);
                    Action action = resolveAction(group, score);
                    loudAction("⚠⚠⚠ UNSAFE (score-gated → " + action + ")",
                            className, "unsafe", group, score);
                    if (action == Action.ERASE)   return emptyClass(classfileBuffer);
                    if (action == Action.DISABLE)  return disableAllMethods(classfileBuffer);
                    // ALLOW — just watching
                    return null;
                }
            }

            // ════════════════════════════════════════════════════════════════
            //  SCORE-GATED DETECTION PIPELINE
            //
            //  All of the checks below add threat score and then let
            //  resolveAction() decide what to do based on total group score.
            //  Nothing here is an instant kill.
            // ════════════════════════════════════════════════════════════════

            // ── TRANSFORMATION SERVICE — score + watch ────────────────────────
            if (isTransformService(classfileBuffer)) {
                String group = extractGroup(className);
                int score = addThreat(group);
                Action action = resolveAction(group, score);
                log("WATCH", String.format(
                        "TransformationService detected: %-50s | group=%-20s | score=%d | verdict=%s",
                        className, group, score, action));
                if (action == Action.ERASE)   return emptyClass(classfileBuffer);
                if (action == Action.DISABLE)  return disableSafe(classfileBuffer);
                return null; // score too low to act yet
            }

            // ── REAL TRANSFORMER — score + act ───────────────────────────────
            if (isRealTransformer(classfileBuffer)
                    && !className.startsWith("org/gradle/")
                    && !className.startsWith("cpw/mods/")
                    && !className.startsWith("net/minecraftforge/")
                    && !className.startsWith("net/neoforged/")) {
                String group = extractGroup(className);
                int score = addThreat(group);
                Action action = resolveAction(group, score);
                loudAction("⚠ TRANSFORMER (score-gated → " + action + ")",
                        className, "transformer", group, score);
                if (action == Action.ERASE)   return emptyClass(classfileBuffer);
                if (action == Action.DISABLE)  return disableSafe(classfileBuffer);
                return null;
            }

            // ── COREMOD ENTRY — score + act ──────────────────────────────────
            if (isCoremodEntry(classfileBuffer)) {
                String group = extractGroup(className);
                int score = addThreat(group);
                Action action = resolveAction(group, score);
                loudAction("⚠ COREMOD ENTRY (score-gated → " + action + ")",
                        className, "coremod-entry", group, score);
                if (action == Action.ERASE)   return emptyClass(classfileBuffer);
                if (action == Action.DISABLE)  return disableSafe(classfileBuffer);
                return null;
            }

            // ── ASM MANIPULATOR — score + act ────────────────────────────────
            if (isASMManipulator(classfileBuffer)
                    && !className.startsWith("org/gradle/")
                    && !className.startsWith("cpw/mods/")
                    && !className.startsWith("net/minecraftforge/")
                    && !className.startsWith("net/neoforged/")
                    && !className.startsWith("org/objectweb/")) {
                String group = extractGroup(className);
                int score = addThreat(group);
                Action action = resolveAction(group, score);
                loudAction("⚠ ASM MANIPULATOR (score-gated → " + action + ")",
                        className, "asm", group, score);
                if (action == Action.ERASE)   return emptyClass(classfileBuffer);
                if (action == Action.DISABLE)  return disableSafe(classfileBuffer);
                return null;
            }

            // ── TARGETED MIXIN DEFENSE — score + act ─────────────────────────
            if (hasMixinInjection(classfileBuffer)
                    && !className.startsWith("net/mcreator/transfinityimproved/")
                    && !className.startsWith("net/minecraft/")
                    && !className.startsWith("org/spongepowered/")
                    && !className.startsWith("com/mojang/")) {

                // Only target dangerous game areas
                if (className.contains("Entity")
                        || className.contains("LivingEntity")
                        || className.contains("Player")
                        || className.contains("Health")
                        || className.contains("Navigation")) {

                    String group = extractGroup(className);
                    int score = addThreat(group);
                    Action action = resolveAction(group, score);
                    loudAction("⚠ TARGETED MIXIN (score-gated → " + action + ")",
                            className, "mixin-targeted", group, score);
                    if (action == Action.ERASE)   return emptyClass(classfileBuffer);
                    if (action == Action.DISABLE)  return disableSafe(classfileBuffer);
                    return null;
                }
            }

            // ── VISITOR NAME HEURISTIC — score + act ─────────────────────────
            if ((className.contains("ClassVisitor")
                    || className.contains("MethodVisitor"))
                    && !className.startsWith("org/objectweb/")) {

                String group = extractGroup(className);
                int score = addThreat(group);
                Action action = resolveAction(group, score);
                loudAction("⚠ VISITOR NAME (score-gated → " + action + ")",
                        className, "visitor-name", group, score);
                if (action == Action.ERASE)   return emptyClass(classfileBuffer);
                if (action == Action.DISABLE)  return disableSafe(classfileBuffer);
                return null;
            }

            // ── MIXIN CLASS NAME — score + act ───────────────────────────────
            if (className.toLowerCase().contains("mixin")
                    && !className.startsWith("org/spongepowered/")
                    && !className.startsWith("net/mcreator/transfinityimproved/")
                    && (className.contains("LivingEntity")
                    || className.contains("PlayerEntity")
                    || className.contains("ServerPlayer")
                    || className.contains("LocalPlayer"))) {

                String group = extractGroup(className);
                int score = addThreat(group);
                Action action = resolveAction(group, score);
                loudMixinAlert(className);
                loudAction("⚠ MIXIN CLASS (score-gated → " + action + ")",
                        className, "mixin", group, score);
                if (action == Action.ERASE)   return emptyClass(classfileBuffer);
                if (action == Action.DISABLE)  return disableSafe(classfileBuffer);
                return null;
            }

            // ════════════════════════════════════════════════════════════════
            //  LEGACY SUSPICION HEURISTIC (name-based, lower priority)
            // ════════════════════════════════════════════════════════════════
            String reason = evaluateSuspicion(className);

            if (reason == null) return null;

            if (reason.equals("mixin")) {
                loudMixinAlert(className);
            }

            String group    = extractGroup(className);
            int    newScore = addThreat(group);
            Action action   = resolveAction(group, newScore);

            switch (action) {

                case ERASE: {
                    loudAction("✖✖✖  E R A S E", className, reason, group, newScore);
                    return emptyClass(classfileBuffer);
                }

                case DISABLE: {
                    loudAction("⚠⚠  D I S A B L E", className, reason, group, newScore);
                    if (className.contains("MyLib2")) {
                        return disableMyLib2(classfileBuffer);
                    }
                    return disableAllMethods(classfileBuffer);
                }

                default: {
                    log("WATCH", String.format(
                            "%-55s | reason=%-22s | group=%-20s | groupScore=%d",
                            className, reason, group, newScore));
                    return null;
                }
            }
        }

        // --------------------------------------------------------------------
        //  Suspicion rules — returns a reason string, or null if class is clean
        // --------------------------------------------------------------------
        private static String evaluateSuspicion(String className) {
            if (className.contains("Mixin")
                    || className.startsWith("org/spongepowered/asm")
                    || className.startsWith("org/spongepowered/mixin")) {
                return "mixin";
            }

            if (className.contains("MyLib2"))        return "known-bad-lib";
            if (className.contains("MyPlugin"))      return "plugin-transformer";
            if (className.contains("MyXformer"))     return "explicit-transformer";
            if (className.contains("ClassVisitor"))  return "asm-visitor";
            if (className.contains("MethodVisitor")) return "asm-method-visitor";
            if (className.contains("ByteBuddy"))     return "bytebuddy-agent";
            if (className.contains("javassist"))     return "javassist-agent";

            if (className.contains("Agent")
                    && !className.startsWith("agent/")
                    && !className.startsWith("org/gradle/"))
                return "agent-class";

            if (className.contains("Instrumentation")) return "instrumentation-hook";

            return null;
        }

        // --------------------------------------------------------------------
        //  Group threat accounting
        // --------------------------------------------------------------------

        private static String extractGroup(String className) {
            String[] parts = className.split("/");
            if (parts.length >= 2) return parts[0] + "/" + parts[1];
            return parts[0];
        }

        private int addThreat(String group) {
            AtomicInteger score = groupScores.computeIfAbsent(
                    group, k -> new AtomicInteger(0));
            int newScore = score.addAndGet(THREAT_PER_HIT);
            log("THREAT", String.format("Group %-30s | +%d → total score %d",
                    group, THREAT_PER_HIT, newScore));
            return newScore;
        }

        private Action resolveAction(String group, int score) {
            Action fresh;
            if      (score > ERASE_THRESHOLD)    fresh = Action.ERASE;
            else if (score >= DISABLE_THRESHOLD)  fresh = Action.DISABLE;
            else                                  fresh = Action.ALLOW;

            groupVerdict.merge(group, fresh, (existing, incoming) ->
                    incoming.ordinal() > existing.ordinal() ? incoming : existing);

            return groupVerdict.get(group);
        }
    }

    // ========================================================================
    //  Bytecode patch utilities
    // ========================================================================

    private static byte[] emptyClass(byte[] original) {
        ClassReader cr = new ClassReader(original);
        ClassWriter cw = new ClassWriter(0);

        cr.accept(new ClassVisitor(ASM_API, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String desc,
                                             String sig, String[] exceptions) {
                if (name.equals("<init>")) {
                    MethodVisitor mv = super.visitMethod(access, name, desc, sig, exceptions);
                    mv.visitCode();
                    mv.visitVarInsn(Opcodes.ALOAD, 0);
                    mv.visitMethodInsn(Opcodes.INVOKESPECIAL,
                            "java/lang/Object", "<init>", "()V", false);
                    mv.visitInsn(Opcodes.RETURN);
                    mv.visitMaxs(1, 1);
                    mv.visitEnd();
                    return null;
                }
                return null;
            }
        }, 0);

        return cw.toByteArray();
    }

    private static byte[] disableAllMethods(byte[] original) {
        ClassReader cr = new ClassReader(original);
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);

        cr.accept(new ClassVisitor(ASM_API, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String desc,
                                             String sig, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, desc, sig, exceptions);

                if (name.equals("<init>") || name.equals("<clinit>")) return mv;

                return new MethodVisitor(ASM_API, mv) {

                    @Override
                    public void visitCode() {
                        super.visitCode();

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
                            default:
                                mv.visitInsn(Opcodes.ACONST_NULL);
                                mv.visitInsn(Opcodes.ARETURN);   break;
                        }
                        mv.visitMaxs(2, 1);
                        mv.visitEnd();
                    }

                    @Override public void visitInsn(int op)                                          {}
                    @Override public void visitVarInsn(int op, int v)                               {}
                    @Override public void visitMethodInsn(int op, String o, String n, String d, boolean i) {}
                    @Override public void visitFieldInsn(int op, String o, String n, String d)      {}
                    @Override public void visitJumpInsn(int op, Label l)                            {}
                    @Override public void visitLabel(Label l)                                       {}
                    @Override public void visitMaxs(int s, int l)                                   {}
                    @Override public void visitTypeInsn(int op, String type)                        {}
                    @Override public void visitLdcInsn(Object cst)                                  {}
                    @Override public void visitIntInsn(int op, int operand)                         {}
                    @Override public void visitIincInsn(int v, int inc)                             {}
                };
            }
        }, ClassReader.EXPAND_FRAMES);

        return cw.toByteArray();
    }

    private static byte[] disableSafe(byte[] original) {
        ClassReader cr = new ClassReader(original);
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);

        cr.accept(new ClassVisitor(ASM_API, cw) {

            @Override
            public MethodVisitor visitMethod(int access, String name, String desc,
                                             String sig, String[] exceptions) {

                MethodVisitor mv = super.visitMethod(access, name, desc, sig, exceptions);

                if (name.equals("<init>") || name.equals("<clinit>")) return mv;

                return new MethodVisitor(ASM_API, mv) {

                    @Override
                    public void visitCode() {
                        super.visitCode();

                        Type returnType = Type.getReturnType(desc);

                        switch (returnType.getSort()) {

                            case Type.VOID:
                                mv.visitInsn(Opcodes.RETURN);
                                break;

                            case Type.BOOLEAN:
                            case Type.INT:
                            case Type.BYTE:
                            case Type.CHAR:
                            case Type.SHORT:
                                mv.visitInsn(Opcodes.ICONST_0);
                                mv.visitInsn(Opcodes.IRETURN);
                                break;

                            case Type.LONG:
                                mv.visitInsn(Opcodes.LCONST_0);
                                mv.visitInsn(Opcodes.LRETURN);
                                break;

                            case Type.FLOAT:
                                mv.visitInsn(Opcodes.FCONST_0);
                                mv.visitInsn(Opcodes.FRETURN);
                                break;

                            case Type.DOUBLE:
                                mv.visitInsn(Opcodes.DCONST_0);
                                mv.visitInsn(Opcodes.DRETURN);
                                break;

                            default:
                                String type = returnType.getInternalName();

                                if ("java/util/List".equals(type)) {
                                    mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                            "java/util/Collections",
                                            "emptyList",
                                            "()Ljava/util/List;",
                                            false);
                                } else if ("java/util/Set".equals(type)) {
                                    mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                            "java/util/Collections",
                                            "emptySet",
                                            "()Ljava/util/Set;",
                                            false);
                                } else if ("java/util/Map".equals(type)) {
                                    mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                            "java/util/Collections",
                                            "emptyMap",
                                            "()Ljava/util/Map;",
                                            false);
                                } else {
                                    mv.visitInsn(Opcodes.ACONST_NULL);
                                }

                                mv.visitInsn(Opcodes.ARETURN);
                                break;
                        }

                        mv.visitMaxs(2, 1);
                        mv.visitEnd();
                    }

                    @Override public void visitInsn(int op) {}
                    @Override public void visitVarInsn(int op, int v) {}
                    @Override public void visitMethodInsn(int op, String o, String n, String d, boolean i) {}
                    @Override public void visitFieldInsn(int op, String o, String n, String d) {}
                    @Override public void visitJumpInsn(int op, Label l) {}
                    @Override public void visitLabel(Label l) {}
                    @Override public void visitMaxs(int s, int l) {}
                    @Override public void visitTypeInsn(int op, String type) {}
                    @Override public void visitLdcInsn(Object cst) {}
                    @Override public void visitIntInsn(int op, int operand) {}
                    @Override public void visitIincInsn(int v, int inc) {}
                };
            }

        }, ClassReader.EXPAND_FRAMES);

        return cw.toByteArray();
    }

    private static byte[] disableMyLib2(byte[] classfileBuffer) {
        return disableAllMethods(classfileBuffer);
    }

    // ========================================================================
    //  Logging helpers
    // ========================================================================

    private static void log(String tag, String msg) {
        System.out.printf("[AGENT | %-18s] %s%n", tag, msg);
    }

    private static void banner(String msg) {
        String bar = "═".repeat(60);
        System.out.println("\n╔" + bar + "╗");
        System.out.printf( "║  %-58s  ║%n", msg);
        System.out.println("╚" + bar + "╝\n");
    }

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
