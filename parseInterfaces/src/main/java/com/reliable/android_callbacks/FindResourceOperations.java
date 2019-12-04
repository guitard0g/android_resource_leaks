package com.reliable.android_callbacks;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.ImportDeclaration;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.Name;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.ast.type.Type;
import com.github.javaparser.metamodel.ImportDeclarationMetaModel;
import com.github.javaparser.resolution.UnsolvedSymbolException;
import com.github.javaparser.resolution.declarations.ResolvedReferenceTypeDeclaration;
import com.github.javaparser.resolution.types.ResolvedReferenceType;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.core.resolution.Context;
import com.github.javaparser.symbolsolver.javaparser.Navigator;
import com.github.javaparser.symbolsolver.javaparsermodel.contexts.CompilationUnitContext;
import com.github.javaparser.symbolsolver.model.resolution.TypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.*;
import com.github.javaparser.utils.CodeGenerationUtils;
import com.github.javaparser.utils.SourceRoot;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.*;
import java.util.*;

public class FindResourceOperations {
    private static String[] openers = {"start","request","lock","open","register","acquire","enable"};
    private static String[] closers = {"end","abandon","cancel","clear","close","disable","finish","recycle","release","remove","stop","unload","unlock","unmount","unregister"};
    private static String[] roots = {"./src/main/resources/javaSource/android", "./src/main/resources/javaSource/androidx"};
    private static String[] root_pieces;
    private static String currRoot;
    private static Map<String, ResourcePair> suffixToPair = new HashMap<>();
    private static Map<String, ArrayList<ClassOrInterfaceType>> classToInheritance = new HashMap<>();


    public static void main(String[] args) {
        try {
            parseEntireProject();
//            for (String root: roots) {
//                root_pieces = root.split("/");
//                currRoot = root;
//                Files.walk(Paths.get(".", root)).filter(Files::isRegularFile)
//                        .forEach(FindResourceOperations::analyzeInheritanceHierarchy);
//                Files.walk(Paths.get(".", root)).filter(Files::isRegularFile)
//                        .forEach(FindResourceOperations::findResourceOperations);
//            }
        } catch (IOException e) {
            System.out.println("ERROR IO Exceoption");
            System.exit(1);
        }
    }

    public static void analyzeInheritanceHierarchy(Path file) {
        FileInfo fi = getFileInfo(file);
        for (TypeDeclaration type:
                fi.cu.getTypes()) {
            if (type.isClassOrInterfaceDeclaration()) {
                ClassOrInterfaceDeclaration casted_type = (ClassOrInterfaceDeclaration)type;
                String key = fi.basePkg + " ## " + fi.sourceFile + " ## " + casted_type.getNameAsString();
                ArrayList<ClassOrInterfaceType> inheritance = new ArrayList<>();
                for (Node n: casted_type.getExtendedTypes()) {
                    // "extended" extends this current type in the compilation unit
                    ClassOrInterfaceType extended = (ClassOrInterfaceType)n;
                    inheritance.add(extended);
                }
                for (Node n: casted_type.getImplementedTypes()) {
                    // "extended" extends this current type in the compilation unit
                    ClassOrInterfaceType implemented = (ClassOrInterfaceType)n;
                    inheritance.add(implemented);
                }
                classToInheritance.put(key, inheritance);
            }
        }
    }

    public static void findResourceOperations(Path file) {
        FileInfo fi = getFileInfo(file);

        // go through all method declarations
        for (TypeDeclaration type:
             fi.cu.getTypes()) {
            NodeList<BodyDeclaration<?>> members = type.getMembers();
            for (BodyDeclaration<?> member: members) {
                if (member.isMethodDeclaration()) {
                    // method name
                    String name = ((MethodDeclaration) member).getName().asString();
                    boolean found = false;
                    MethodDeclaration casted_member = (MethodDeclaration)member;

                    // Check if method is an opener
                    for (String opener :
                            openers) {
                        if (name.startsWith(opener)) {
                            found = true;
                            ResourcePair.putOpener(
                                    suffixToPair, name, fi.basePkg, fi.sourceFile, rootAPIName(),
                                    FindResourceOperations.getReturnType(
                                            casted_member.getType(),
                                            fi.cu, fi.basePkg, fi.sourceFile
                                    )
                            );
                            break;
                        }
                    }

                    // Check if method is a closer
                    if (!found) {
                        for (String closer :
                                closers) {
                            if (name.startsWith(closer)) {
                                ResourcePair.putCloser(suffixToPair, name, fi.basePkg, fi.sourceFile, rootAPIName());
                                break;
                            }
                        }
                    }
                }
            }
        }

        Path pair_file = CodeGenerationUtils.mavenModuleRoot(ScanCallbackInterfaces.class).resolve("output/pairs_new_" + root_pieces[root_pieces.length - 1] + ".txt");
        BufferedWriter pair_writer;
        try {
            pair_writer = Files.newBufferedWriter(pair_file, Charset.forName("UTF-8"));
            for (String key:
                    suffixToPair.keySet()) {
                ResourcePair pair = suffixToPair.get(key);
                if (pair.isComplete()) {
                    pair_writer.append(pair.toString());
                }
            }
            pair_writer.flush();
            pair_writer.close();
        } catch(IOException ex){
            ex.printStackTrace();
            System.exit(1);
        }
    }

    private static Optional<String> getReturnType(Type type, CompilationUnit cu, String base_pkg, String sourceFile) {
        if (!type.isClassOrInterfaceType()) {
            return Optional.empty();
        } else {
            ClassOrInterfaceType casted_type = ((ClassOrInterfaceType)type);
            // check all imported objects
            for(ImportDeclaration i: cu.getImports()) {
                // each one should have child nodes indicating the items being imported
                for(Node n: i.getChildNodes()) {
                    // Check each item to see if it's the same name as our type signature.
                    // If so, format the name and return it.
                    Name name = (Name)n;
                    if (name.getIdentifier().equals(casted_type.getNameAsString())) {
                        return Optional.of(FindResourceOperations.formatName(name));
                    }
                }
            }
            String formatted_base_pkg = "android.*/" + base_pkg.replace('.', '/');
            String formatted_name = casted_type.getNameAsString().replace('.', '/');
            return Optional.of("L" + formatted_base_pkg + "/" + formatted_name + ";");
        }
    }

    private static String formatName(Name name) {
        String arr[] = name.asString().split("\\.");
        arr[0] = arr[0] + ".*";
        return "L" + String.join("/", arr) + ";";
    }

    private static FileInfo getFileInfo(Path file) {
        String filename = file.toString();
        int i = filename.lastIndexOf('/');
        String dir = filename.substring(0, i);
        String source_file = filename.substring(i+1);

        String[] path_components = dir.split("/");
        int path_length_difference = path_components.length - root_pieces.length;
        String[] relative_path = Arrays.copyOfRange(
                path_components,
                path_components.length - path_length_difference + 1,
                path_components.length );
        String base_pkg = String.join(".", relative_path);

        SourceRoot sourceRoot = new SourceRoot(Paths.get(".", currRoot));
        CompilationUnit cu = sourceRoot.parse(base_pkg, source_file);
        return new FileInfo(base_pkg, source_file, cu);
    }

    private static void parseEntireProject() throws IOException {
        // Path root = Paths.get(".", "./src/main/resources/javaSource/android");
        Path root = Paths.get(".", "src/main/resources/javaSource/android");
        Path sqliteDB = Paths.get(".", "src/main/resources/javaSource/android/database/sqlite/SQLiteDatabase.java");
        Path sqliteClosable = Paths.get(".", "src/main/resources/javaSource/android/database/sqlite/SQLiteClosable.java");

        TypeSolver reflectionTypeSolver = new ReflectionTypeSolver();
        TypeSolver javaParserSolver = new JavaParserTypeSolver(new File("src/main/resources/javaSource/android"));
        MemoryTypeSolver memoryTypeSolver = new MemoryTypeSolver();
        reflectionTypeSolver.setParent(reflectionTypeSolver);
        javaParserSolver.setParent(reflectionTypeSolver);

        CombinedTypeSolver combinedSolver = new CombinedTypeSolver();
        combinedSolver.add(reflectionTypeSolver);
        combinedSolver.add(javaParserSolver);
        combinedSolver.add(memoryTypeSolver);

        JavaSymbolSolver symbolSolver = new JavaSymbolSolver(combinedSolver);
        ParserConfiguration config = new ParserConfiguration();
        config.setSymbolResolver(symbolSolver);
        StaticJavaParser.setConfiguration(config);

        CompilationUnit cu = StaticJavaParser.parse(sqliteClosable);

        Files.walk(root).filter(Files::isRegularFile).forEach(file -> {
            try {
                final CompilationUnit curr = StaticJavaParser.parse(file);
                curr.findAll(ClassOrInterfaceDeclaration.class).forEach(ie -> {
                    ResolvedReferenceTypeDeclaration rrt = ie.resolve().asReferenceType();
                    memoryTypeSolver.addDeclaration(rrt.getQualifiedName(), rrt);
                });
            } catch (IOException e) {/* ignore */}
        });

        cu.findAll(ClassOrInterfaceType.class).forEach(ie -> {
            try {
                System.out.println(ie.resolve().asReferenceType().getQualifiedName());
            } catch (UnsolvedSymbolException e) {
                int test = 1;
            }
        });
    }

    private static String rootAPIName() {
        return root_pieces[root_pieces.length - 1];
    }
}

class FileInfo {
    public String basePkg;
    public String sourceFile;
    public CompilationUnit cu;

    public FileInfo(String basePkg, String sourceFile, CompilationUnit cu) {
        this.basePkg = basePkg;
        this.sourceFile = sourceFile;
        this.cu = cu;
    }
}

class ResourcePair {
    public String opener;
    public HashSet<String> openers = new HashSet<>();
    public HashSet<String> closers = new HashSet<>();
    public String closer;
    public String base_pkg;
    public String source;
    public String root;
    public Optional<String> type;

    public ResourcePair(String opener, String closer, String base_pkg, String source, String root) {
        if (opener != null) {
            this.openers.add(opener);
        }
        if (closer != null) {
            this.closers.add(closer);
        }
        this.opener = opener;
        this.closer = closer;
        this.base_pkg = base_pkg;
        this.source = source.split("\\.")[0];
        this.root = root;
    }

    public boolean isComplete() {
        return !this.openers.isEmpty() && !this.closers.isEmpty();
    }

    public String toString() {
        // We use "Landroid.*" as our prefix because we will use these class names as patterns
        // for matching in our analysis
        String formatted_base_pkg = this.root + ".*/" + this.base_pkg.replace('.', '/');

        StringBuilder result = new StringBuilder();
        for (String opener: this.openers) {
            for (String closer: this.closers) {
                result.append("L");
                result.append(formatted_base_pkg);
                result.append("/");
                result.append(this.source);
                result.append(";");
                result.append(" ## ");
                result.append(opener);
                result.append(" ## ");
                result.append(closer);
                result.append(" ## ");
                result.append(this.isUserFacing() ? "User" : "Internal");
                result.append('\n');
            }
        }
        return result.toString();
    }

    public static String getSuffix(String name) {
        String[] pieces = name.split("(?=[A-Z])");
        return String.join("", Arrays.copyOfRange(pieces, 1, pieces.length));
    }

    public boolean isUserFacing() {
        // If this method pair returns a concrete, manageable object,
        // we'll assume it's something a user is using to explicitly
        // manage resources.
        return type.isPresent();
    }

    public static void putOpener(Map<String,
                                 ResourcePair> suffixToPair,
                                 String opener,
                                 String base_pkg,
                                 String source,
                                 String rootAPI,
                                 Optional<String> type
    ) {
        ResourcePair pair;
        String key = base_pkg + "##" + source + "##" + ResourcePair.getSuffix(opener);
        pair = suffixToPair.get(key);
        if (pair == null) {
            suffixToPair.put(key, new ResourcePair(opener, null, base_pkg, source, rootAPI));
            pair = suffixToPair.get(key);
        } else {
            pair.openers.add(opener);
        }
        pair.type = type;
    }

    public static void putCloser(Map<String,
                                 ResourcePair> suffixToPair,
                                 String closer,
                                 String base_pkg,
                                 String source,
                                 String rootAPI
    ) {
        String key = base_pkg + "##" + source + "##" + ResourcePair.getSuffix(closer);
        ResourcePair existing = suffixToPair.get(key);
        if (existing != null) {
            existing.closers.add(closer);
        } else {
            suffixToPair.put(key, new ResourcePair(null, closer, base_pkg, source, rootAPI));
        }
    }
}
