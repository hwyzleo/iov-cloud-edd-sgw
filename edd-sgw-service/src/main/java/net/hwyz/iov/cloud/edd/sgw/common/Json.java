package net.hwyz.iov.cloud.edd.sgw.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 内部 JSON 与摘要工具。
 * <p>
 * 归一化序列化用于生成稳定校验和与结构化差异比较。
 *
 * @author hwyz_leo
 */
public final class Json {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .setSerializationInclusion(JsonInclude.Include.NON_NULL)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
            .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    private Json() {
    }

    /**
     * 对象转 JSON
     *
     * @param value 对象
     * @return JSON 字符串
     */
    public static String write(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (Exception e) {
            throw new IllegalStateException("JSON 序列化失败", e);
        }
    }

    /**
     * JSON 转对象
     *
     * @param json  JSON
     * @param clazz 目标类型
     * @param <T>   类型
     * @return 对象
     */
    public static <T> T read(String json, Class<T> clazz) {
        try {
            return MAPPER.readValue(json, clazz);
        } catch (Exception e) {
            throw new IllegalStateException("JSON 反序列化失败", e);
        }
    }

    /**
     * JSON 转对象列表
     *
     * @param json  JSON
     * @param clazz 元素类型
     * @param <T>   类型
     * @return 列表
     */
    public static <T> java.util.List<T> readList(String json, Class<T> clazz) {
        try {
            return MAPPER.readValue(json, MAPPER.getTypeFactory().constructCollectionType(java.util.List.class, clazz));
        } catch (Exception e) {
            throw new IllegalStateException("JSON 反序列化失败", e);
        }
    }

    /**
     * 解析 JSON 树
     *
     * @param json JSON
     * @return 树
     */
    public static com.fasterxml.jackson.databind.JsonNode tree(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (Exception e) {
            throw new IllegalStateException("JSON 解析失败", e);
        }
    }

    /**
     * 对象类型转换（VO 与领域模型之间的同构映射）
     *
     * @param value 源对象
     * @param clazz 目标类型
     * @param <T>   类型
     * @return 目标对象
     */
    public static <T> T convert(Object value, Class<T> clazz) {
        return MAPPER.convertValue(value, clazz);
    }

    /**
     * 稳定序列化
     *
     * @param value 对象
     * @return 稳定 JSON
     */
    public static String canonical(Object value) {
        return write(value);
    }

    /**
     * SHA-256 摘要
     *
     * @param value 文本
     * @return 十六进制摘要
     */
    public static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                builder.append(Character.forDigit((b >> 4) & 0xF, 16));
                builder.append(Character.forDigit(b & 0xF, 16));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    /**
     * 截断文本用于脱敏错误信息
     *
     * @param value     文本
     * @param maxLength 最大长度
     * @return 截断后的文本
     */
    public static String truncate(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        return value.length() <= maxLength ? value : value.substring(0, maxLength);
    }

}
