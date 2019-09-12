package com.reliable.android_callbacks;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.utils.CodeGenerationUtils;
import com.github.javaparser.utils.SourceRoot;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.*;
import java.util.*;

public class FindResourceOperations {
    private static String[] openers = {"start","request","lock","open","register","acquire","enable"};
    private static String[] closers = {"end","abandon","cancel","clear","close","disable","finish","recycle","release","remove","stop","unload","unlock","unmount","unregister"};
    private static String root = "./src/main/resources/javaSource/android";
    private static String[] root_pieces = root.split("/");
    private static Map<String, ResourcePair> suffixToPair = new HashMap<>();


    public static void main(String[] args) {
        try {
            Files.walk(Paths.get(".", root)).filter(Files::isRegularFile)
                    .forEach(FindResourceOperations::findResourceOperations);
        } catch (IOException e) {
            System.out.println("ERROR IO Exceoption");
            System.exit(1);
        }
    }

    public static void findResourceOperations(Path file) {
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

        SourceRoot sourceRoot = new SourceRoot(Paths.get(".", root));
        CompilationUnit cu = sourceRoot.parse(base_pkg, source_file);

        // go through all method declarationa
        for (TypeDeclaration type:
             cu.getTypes()) {
            NodeList<BodyDeclaration<?>> members = type.getMembers();
            for (BodyDeclaration<?> member: members) {
                if (member.isMethodDeclaration()) {
                    // method name
                    String name = ((MethodDeclaration) member).getName().asString();
                    boolean found = false;

                    // Check if method is an opener
                    for (String opener :
                            openers) {
                        if (name.startsWith(opener)) {
                            found = true;
                            ResourcePair.putOpener(suffixToPair, name, base_pkg, source_file);
                            break;
                        }
                    }

                    // Check if method is a closer
                    if (!found) {
                        for (String closer :
                                closers) {
                            if (name.startsWith(closer)) {
                                ResourcePair.putCloser(suffixToPair, name, base_pkg, source_file);
                                break;
                            }
                        }
                    }
                }
            }
        }

        Path pair_file = CodeGenerationUtils.mavenModuleRoot(ScanCallbackInterfaces.class).resolve("output/pairs.txt");
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
}

class ResourcePair {
    public String opener;
    public HashSet<String> openers = new HashSet<>();
    public HashSet<String> closers = new HashSet<>();
    public String closer;
    public String base_pkg;
    public String source;

    public ResourcePair(String opener, String closer, String base_pkg, String source) {
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
    }

    public boolean isComplete() {
        return !this.openers.isEmpty() && !this.closers.isEmpty();
    }

    public String toString() {
        // We use "Landroid.*" as our prefix because we will use these class names as patterns
        // for matching in our analysis
        String formatted_base_pkg = "android.*/" + this.base_pkg.replace('.', '/');

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
                result.append('\n');
            }
        }
        return result.toString();
    }

    public static String getSuffix(String name) {
        String[] pieces = name.split("(?=[A-Z])");
        return String.join("", Arrays.copyOfRange(pieces, 1, pieces.length));
    }

    public static void putOpener(Map<String, ResourcePair> suffixToPair, String opener, String base_pkg, String source) {
        String key = base_pkg + "##" + source + "##" + ResourcePair.getSuffix(opener);
        ResourcePair existing = suffixToPair.get(key);
        if (existing != null) {
            existing.openers.add(opener);
        } else {
            suffixToPair.put(key, new ResourcePair(opener, null, base_pkg, source));
        }
    }

    public static void putCloser(Map<String, ResourcePair> suffixToPair, String closer, String base_pkg, String source) {
        String key = base_pkg + "##" + source + "##" + ResourcePair.getSuffix(closer);
        ResourcePair existing = suffixToPair.get(key);
        if (existing != null) {
            existing.closers.add(closer);
        } else {
            suffixToPair.put(key, new ResourcePair(null, closer, base_pkg, source));
        }
    }
}
