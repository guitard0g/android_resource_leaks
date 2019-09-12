package com.reliable.android_callbacks;

import com.github.javaparser.ParseProblemException;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.resolution.declarations.ResolvedMethodDeclaration;
import com.github.javaparser.utils.CodeGenerationUtils;
import com.github.javaparser.utils.SourceRoot;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.*;
import java.util.*;


public class ScanCallbackInterfaces {
    public static void main(String[] args) throws IOException {
        // file of callback interfaces
        Path callbacks_file = CodeGenerationUtils
                .mavenModuleRoot(ScanCallbackInterfaces.class)
                .resolve("src/main/resources/AndroidCallbacks.txt");

        ArrayList<InterfaceName> interfaces = new ArrayList<>();
        try(BufferedReader reader = Files.newBufferedReader(callbacks_file, Charset.forName("UTF-8"))){
            String currentLine;
            String fullInterfaceName;
            String[] interfaceAndSubInterface;
            String packagePath;

            while((currentLine = reader.readLine()) != null) {
                int splitIndex = currentLine.lastIndexOf('.');
                if (splitIndex == -1)
                    continue; // broken String, don't bother

                // path.to.package.InterfaceName$PossibleSubInterface
                packagePath = currentLine.substring(0, splitIndex);
                fullInterfaceName = currentLine.substring(splitIndex+1);
                interfaceAndSubInterface = fullInterfaceName.split("\\$");

                interfaces.add(new InterfaceName(
                        packagePath,
                        interfaceAndSubInterface[0],
                        interfaceAndSubInterface.length > 1
                                ? interfaceAndSubInterface[1]
                                : null
                        )
                );
            }
        } catch(IOException ex){
            ex.printStackTrace();
            System.exit(1);
        }


        Path sourceCodeDir = CodeGenerationUtils
                .mavenModuleRoot(ScanCallbackInterfaces.class)
                .resolve("src/main/resources/javaSource");

        Map<String, List<MethodDeclaration>> results = scanCallbackInterfaces(
                        sourceCodeDir,
                        interfaces );

        Path output_file = CodeGenerationUtils
                .mavenModuleRoot(ScanCallbackInterfaces.class)
                .resolve("output/CallbackMethods.txt");

        writeResults(results, output_file);

        System.out.println("all done");
    }


    public static Map<String, List<MethodDeclaration>> scanCallbackInterfaces(
            Path sourceDir,
            ArrayList<InterfaceName> interfaces
    ) {
        SourceRoot sourceRoot = new SourceRoot(sourceDir);
        Map<String, List<MethodDeclaration>> interfaceToMethod = new HashMap<>();

        String key;
        List<MethodDeclaration> value;
        for (InterfaceName curr
            : interfaces) {
            ClassOrInterfaceDeclaration subInterfaceDecl = null;
            ClassOrInterfaceDeclaration interfaceDecl = findInterface(
                    sourceRoot,
                    curr.getPkg(),
                    curr.getClsOrInt()
            );

            if (interfaceDecl == null) {
                continue;
            }

            if (curr.isSubInterface()) {
                subInterfaceDecl = findSubInterface(interfaceDecl, curr.getSubInt()).orElse(null);
                if (subInterfaceDecl == null) {
                    // subInterface not found
                    continue;
                }
            }

            key = formatKeyString(curr.getPkg(), curr.getClsOrInt(), curr.getSubIntOption());
            value = getInterfaceMethods(
                    curr.isSubInterface()
                            ? subInterfaceDecl
                            : interfaceDecl );

            interfaceToMethod.put(key, value);
        }

        return interfaceToMethod;
    }

    private static ClassOrInterfaceDeclaration findInterface(
            SourceRoot sourceRoot,
            String sourcePackage,
            String callbackInterface
    ) {
        CompilationUnit cu;
        Optional<ClassOrInterfaceDeclaration> maybeInterface;
        Optional<ClassOrInterfaceDeclaration> maybeClass;

        try {
            cu = sourceRoot.parse(sourcePackage, callbackInterface + ".java");
            maybeInterface = cu.getInterfaceByName(callbackInterface);
            maybeClass = cu.getClassByName(callbackInterface);
        } catch (ParseProblemException ex) {
            maybeInterface = Optional.empty();
            maybeClass = Optional.empty();
        }

        return maybeInterface.orElse(maybeClass.orElse(null));
    }

    private static Optional<ClassOrInterfaceDeclaration> findSubInterface(
            ClassOrInterfaceDeclaration parentInterface,
            String subInterfaceName
    ) {
        ClassOrInterfaceDeclaration possibleAnswer;

        for ( BodyDeclaration member:
                parentInterface.getMembers() ) {
            if ( member.isClassOrInterfaceDeclaration() ) {
                // current member is some class/interface and not a method or field
                possibleAnswer = (ClassOrInterfaceDeclaration) member;

                if( possibleAnswer.getNameAsString().equals(subInterfaceName) ) {
                    return Optional.of(possibleAnswer);
                }
            }
        }

        return Optional.empty();
    }

    private static ArrayList<MethodDeclaration> getInterfaceMethods(
            ClassOrInterfaceDeclaration outerInterface
    ){
        return new ArrayList<>(outerInterface.getMethods());
    }

    private static String formatKeyString(
            String packageName,
            String outerInterface,
            Optional<String> innerInterface
    ){
        StringBuilder keyBuilder = new StringBuilder();

        keyBuilder.append("L");
        keyBuilder.append(packageName.replace('.', '/'));
        keyBuilder.append("/");
        keyBuilder.append(outerInterface);
        keyBuilder.append("$");
        innerInterface.ifPresentOrElse(
                keyBuilder::append,
                () -> keyBuilder.deleteCharAt(keyBuilder.length() - 1)
        );
        keyBuilder.append(";");

        return keyBuilder.toString();
    }

    private static void writeResults(
            Map<String, List<MethodDeclaration>> results,
            Path outputPath
    ){
        try(BufferedWriter writer = Files.newBufferedWriter(outputPath, Charset.forName("UTF-8"))){
            for (Map.Entry<String, List<MethodDeclaration>> entry:
                 results.entrySet()) {
                // denote new entry
                writer.append("INTERFACE");
                writer.newLine();

                writer.append(entry.getKey());
                writer.newLine();

                for (MethodDeclaration method:
                        entry.getValue()) {
                    writer.append("METHOD");
                    writer.newLine();
                    writer.append(method.getNameAsString());
                    writer.newLine();

                    writer.append("RETURN TYPE");
                    writer.newLine();
                    writer.append(method.getTypeAsString());
                    writer.newLine();

                    for (Parameter param:
                         method.getParameters()) {
                        writer.append("ARG TYPE");
                        writer.newLine();
                        writer.append(param.getTypeAsString());
                        writer.newLine();
                    }
                }
            }
        } catch(IOException ex){
            ex.printStackTrace();
            System.exit(1);
        }
    }

}

class InterfaceName {
    private String packageName;
    private String classOrInterfaceName;
    private String subInterfaceName;
    private boolean isSubInterface;

    InterfaceName(String pkg, String clsOrInt, String subInt) {
        this.packageName = pkg;
        this.classOrInterfaceName = clsOrInt;
        if (subInt != null) {
            this.subInterfaceName = subInt;
            this.isSubInterface = true;
        }
        else {
            this.subInterfaceName = null;
            this.isSubInterface = false;
        }
    }

    public boolean isSubInterface() {
        return this.isSubInterface;
    }

    public String getPkg() {
        return this.packageName;
    }

    public String getClsOrInt() {
        return this.classOrInterfaceName;
    }

    public String getSubInt() {
        return this.subInterfaceName;
    }

    public Optional<String> getSubIntOption() {
        if (this.isSubInterface)
            return Optional.of(this.subInterfaceName);
        return Optional.empty();
    }

}
