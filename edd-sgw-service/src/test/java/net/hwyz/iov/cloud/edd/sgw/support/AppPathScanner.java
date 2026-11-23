package net.hwyz.iov.cloud.edd.sgw.support;

import net.hwyz.iov.cloud.edd.sgw.domain.catalog.SgwAppPathCatalog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * App 侧经 SGW 的请求路径扫描器（EDD-SGW-DSN-CR-003 §19.2.6 TC-003-16；终审修复 B-2）。
 * <p>
 * 终审 B-2 的两个缺陷及本类的修复：
 * <ol>
 *     <li>旧门禁正则 {@code "(/api/[^"\\]*)"} 只匹配 {@code /api/} 字面量 →
 *         漏掉 {@code /unlockVehicle}、{@code /mp/rvc/**}、{@code /mp/account/**} 等；
 *         本类同时采集「{@code request{Get,Post,Put,Delete,Patch}(path: "…")} 上下文路径」与
 *         「{@code /api/…} 字面量（含常量定义，如 AvatarRemoteAPI 的 uploadPath）」，两者取并集。</li>
 *     <li>旧门禁只扫单个 {@code TspApi.swift}；本类支持多源扫描，门禁强制纳入
 *         {@code TspApi.swift}、{@code AvatarRemoteAPI.swift}、{@code VehicleBindingService.swift}。</li>
 * </ol>
 * 一切「无法解析的路径来源」都会被 {@link #unresolvedPathReferences(String)} 暴露，由门禁断言为空，
 * 避免静默漏检（fail-closed）。
 *
 * @author hwyz_leo
 */
public final class AppPathScanner {

    /**
     * iOS 源文件（相对仓库根）：真实发起 SGW 请求的三处
     */
    public static final List<String> IOS_SOURCES = List.of(
            "mp/ios/iov-mp-ios-app/iov/iov/Data/Http/TspApi.swift",
            "mp/ios/iov-mp-ios-app/iov/iov/Domain/Avatar/AvatarRemoteAPI.swift",
            "mp/ios/iov-mp-ios-app/iov/iov/Module/Vehicle/Service/VehicleBindingService.swift");

    /** 全部路径形态字符串字面量（不限 /api/ 前缀） */
    private static final Pattern ANY_PATH_LITERAL = Pattern.compile("\"(/[^\"]*)\"");

    /** 请求上下文中的路径字面量：requestXxx(path: "…") 或 requestXxx(path: tspUrl + "…") */
    private static final Pattern REQUEST_PATH_LITERAL = Pattern.compile(
            "request(?:Get|Post|Put|Delete|Patch)\\s*\\(\\s*path:\\s*"
                    + "(?:AppGlobalState\\.shared\\.tspUrl\\s*\\+\\s*)?\"(/[^\"]*)\"");

    /** 请求上下文中的常量引用：path: self.baseURL() + Self.uploadPath / Self.completePath(...) */
    private static final Pattern REQUEST_SELF_REFERENCE = Pattern.compile(
            "request(?:Get|Post|Put|Delete|Patch)\\s*\\(\\s*path:\\s*[^,\\n]*?Self\\.(\\w+)");

    /** 常量定义：static let uploadPath = "…" */
    private static final Pattern CONSTANT_DEFINITION = Pattern.compile(
            "(?:static\\s+)?let\\s+%s\\s*=\\s*\"(/[^\"]*)\"");

    /** 函数定义（用于解析 completePath(uploadId:) 这类封装） */
    private static final Pattern FUNCTION_DEFINITION = Pattern.compile("(?:static\\s+)?func\\s+%s\\s*\\(");

    /** 函数体内的返回值字面量 */
    private static final Pattern RETURN_LITERAL = Pattern.compile("return\\s+\"(/[^\"]*)\"");

    /** Swift 字符串插值 {@code \(expr)}：路径中的动态段，扫描时剔除 */
    private static final Pattern INTERPOLATION = Pattern.compile("\\\\\\([^)]*\\)");

    private AppPathScanner() {
    }

    /**
     * 扫描多个 iOS 源文件内容，返回经 SGW 的路径集合（已归一化）
     *
     * @param contents 源文件文本
     * @return 归一化后的路径集合（保持出现顺序）
     */
    public static Set<String> scan(String... contents) {
        Set<String> paths = new LinkedHashSet<>();
        for (String content : contents) {
            // 1) 上下文路径：catch /unlockVehicle、/mp/rvc/** 等非 /api/ 前缀
            Matcher request = REQUEST_PATH_LITERAL.matcher(content);
            while (request.find()) {
                paths.add(normalize(request.group(1)));
            }
            // 2) 常量封装的路径（AvatarRemoteAPI）：解析 Self.<name> 引用
            Matcher reference = REQUEST_SELF_REFERENCE.matcher(content);
            while (reference.find()) {
                paths.addAll(resolveSelfReference(content, reference.group(1)));
            }
            // 3) /api/ 字面量（含常量定义本体，如 static let uploadPath = "/api/…"）
            Matcher literal = ANY_PATH_LITERAL.matcher(content);
            while (literal.find()) {
                String normalized = normalize(literal.group(1));
                if (normalized.startsWith("/api/")) {
                    paths.add(normalized);
                }
            }
        }
        return paths;
    }

    /**
     * 扫描文件
     *
     * @param sources 源文件路径
     * @return 归一化后的路径集合
     * @throws IOException 读取失败
     */
    public static Set<String> scanFiles(List<Path> sources) throws IOException {
        List<String> contents = new ArrayList<>();
        for (Path source : sources) {
            contents.add(Files.readString(source, StandardCharsets.UTF_8));
        }
        return scan(contents.toArray(String[]::new));
    }

    /**
     * 定位仓库内的 iOS 源文件（优先 {@code -Diov.monorepo.root}，否则自模块目录向上最多 6 级查找）
     *
     * @param relative 相对仓库根路径
     * @return 源文件路径
     */
    public static Path locate(String relative) {
        String root = System.getProperty("iov.monorepo.root");
        if (root != null && !root.isBlank()) {
            Path candidate = Path.of(root, relative);
            if (Files.exists(candidate)) {
                return candidate;
            }
            throw new IllegalStateException("由 -Diov.monorepo.root 指定的仓库根下不存在 " + relative + "（实际: " + candidate + "）");
        }
        Path current = Path.of("").toAbsolutePath();
        for (int i = 0; i <= 6 && current != null; i++) {
            Path candidate = current.resolve(relative);
            if (Files.exists(candidate)) {
                return candidate;
            }
            current = current.getParent();
        }
        throw new IllegalStateException("未找到 App 源文件 " + relative
                + "；请以仓库根检出或通过 -Diov.monorepo.root 指定（CI 需可读 mp/ios）");
    }

    /**
     * 未被任何清单前缀覆盖的路径
     *
     * @param paths    路径集合
     * @param prefixes 清单
     * @return 未覆盖路径（保持顺序）
     */
    public static Set<String> uncovered(Collection<String> paths,
                                        Collection<SgwAppPathCatalog.AppPrefix> prefixes) {
        return paths.stream()
                .filter(path -> covering(path, prefixes).isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * 命中该路径的清单前缀（应为唯一）
     *
     * @param path     路径
     * @param prefixes 清单
     * @return 命中前缀列表
     */
    public static List<SgwAppPathCatalog.AppPrefix> covering(
            String path, Collection<SgwAppPathCatalog.AppPrefix> prefixes) {
        return prefixes.stream()
                .filter(prefix -> matchesPrefix(path, prefix.prefix()))
                .toList();
    }

    /**
     * 路径是否落在前缀内（段边界感知：{@code /mp/rvc/**} 覆盖 {@code /mp/rvc} 与 {@code /mp/rvc/cmd}，
     * 但不覆盖 {@code /mp/rvcOther}）
     *
     * @param path   路径
     * @param prefix 清单前缀
     * @return 是否覆盖
     */
    public static boolean matchesPrefix(String path, String prefix) {
        if (prefix == null || prefix.isBlank()) {
            return false;
        }
        boolean wildcard = prefix.endsWith("/**");
        String base = wildcard ? prefix.substring(0, prefix.length() - 3) : prefix;
        String normalized = normalize(path);
        if (normalized.equals(base)) {
            return true;
        }
        return normalized.startsWith(base + "/");
    }

    /**
     * 归一化：剔除查询串与 Swift 插值动态段，去掉尾部斜杠
     *
     * @param literal 原始字面量
     * @return 归一化路径
     */
    public static String normalize(String literal) {
        String value = INTERPOLATION.matcher(literal).replaceAll("");
        int query = value.indexOf('?');
        if (query >= 0) {
            value = value.substring(0, query);
        }
        // 插值段被剔除后可能留下连续斜杠（如 /avatar/\(id)/complete → /avatar//complete）
        value = value.replaceAll("/{2,}", "/");
        while (value.length() > 1 && value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        return value;
    }

    /**
     * 未被解析的 {@code Self.<name>} 路径来源（门禁要求为空，避免静默漏检）
     *
     * @param content 源文件文本
     * @return 未解析的常量/函数名
     */
    public static Set<String> unresolvedPathReferences(String content) {
        Set<String> unresolved = new LinkedHashSet<>();
        Matcher reference = REQUEST_SELF_REFERENCE.matcher(content);
        while (reference.find()) {
            if (resolveSelfReference(content, reference.group(1)).isEmpty()) {
                unresolved.add(reference.group(1));
            }
        }
        return unresolved;
    }

    private static List<String> resolveSelfReference(String content, String name) {
        List<String> resolved = new ArrayList<>();
        Matcher constant = Pattern.compile(String.format(CONSTANT_DEFINITION.pattern(), Pattern.quote(name)))
                .matcher(content);
        while (constant.find()) {
            resolved.add(normalize(constant.group(1)));
        }
        if (!resolved.isEmpty()) {
            return resolved;
        }
        Matcher function = Pattern.compile(String.format(FUNCTION_DEFINITION.pattern(), Pattern.quote(name)))
                .matcher(content);
        while (function.find()) {
            Matcher returned = RETURN_LITERAL.matcher(content.substring(function.end()));
            if (returned.find()) {
                resolved.add(normalize(returned.group(1)));
            }
        }
        return resolved;
    }

}
