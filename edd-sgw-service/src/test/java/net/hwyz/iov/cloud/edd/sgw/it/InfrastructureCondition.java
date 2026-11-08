package net.hwyz.iov.cloud.edd.sgw.it;

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * 集成测试基础设施可用性条件。
 * <p>
 * 本机（或 CI 提供的）MySQL 与 Redis 不可用时跳过集成测试，避免在无依赖环境构建失败。
 * 支持通过环境变量覆盖地址：SGW_IT_MYSQL_HOST/PORT、SGW_IT_REDIS_HOST/PORT。
 *
 * @author hwyz_leo
 */
public class InfrastructureCondition implements ExecutionCondition {

    static final String MYSQL_HOST = env("SGW_IT_MYSQL_HOST", "127.0.0.1");

    static final int MYSQL_PORT = Integer.parseInt(env("SGW_IT_MYSQL_PORT", "3306"));

    static final String REDIS_HOST = env("SGW_IT_REDIS_HOST", "127.0.0.1");

    static final int REDIS_PORT = Integer.parseInt(env("SGW_IT_REDIS_PORT", "6379"));

    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
        if (!reachable(MYSQL_HOST, MYSQL_PORT)) {
            return ConditionEvaluationResult.disabled("MySQL 不可用，跳过集成测试: " + MYSQL_HOST + ":" + MYSQL_PORT);
        }
        if (!reachable(REDIS_HOST, REDIS_PORT)) {
            return ConditionEvaluationResult.disabled("Redis 不可用，跳过集成测试: " + REDIS_HOST + ":" + REDIS_PORT);
        }
        return ConditionEvaluationResult.enabled("MySQL 与 Redis 可用");
    }

    private static boolean reachable(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 1000);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static String env(String name, String defaultValue) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? defaultValue : value;
    }

}
