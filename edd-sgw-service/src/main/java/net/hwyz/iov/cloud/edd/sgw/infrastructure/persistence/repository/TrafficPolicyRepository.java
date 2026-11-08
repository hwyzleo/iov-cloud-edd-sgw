package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.LambdaUpdateWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.common.PageSlice;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CircuitBreakerRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RateLimitRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RetryRule;
import net.hwyz.iov.cloud.edd.sgw.domain.model.TrafficPolicy;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper.TrafficPolicyMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.TrafficPolicyPo;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import java.lang.reflect.Type;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * 流量治理策略草稿仓储。
 *
 * @author hwyz_leo
 */
@Repository
public class TrafficPolicyRepository {

    private final TrafficPolicyMapper mapper;

    public TrafficPolicyRepository(TrafficPolicyMapper mapper) {
        this.mapper = mapper;
    }

    public PageSlice<TrafficPolicy> page(int page, int size, String name, Boolean enabled) {
        LambdaQueryWrapper<TrafficPolicyPo> wrapper = new LambdaQueryWrapper<TrafficPolicyPo>()
                .eq(TrafficPolicyPo::getRowValid, true)
                .like(StringUtils.hasText(name), TrafficPolicyPo::getPolicyName, name)
                .eq(enabled != null, TrafficPolicyPo::getEnabled, enabled)
                .orderByAsc(TrafficPolicyPo::getPolicyCode);
        Page<TrafficPolicyPo> result = mapper.selectPage(new Page<>(page, size), wrapper);
        return new PageSlice<>(result.getRecords().stream().map(this::toDomain).toList(),
                result.getTotal(), page, size);
    }

    public List<TrafficPolicy> findAllValid() {
        return mapper.selectList(new LambdaQueryWrapper<TrafficPolicyPo>()
                        .eq(TrafficPolicyPo::getRowValid, true)
                        .orderByAsc(TrafficPolicyPo::getPolicyCode))
                .stream().map(this::toDomain).toList();
    }

    public Optional<TrafficPolicy> findValid(String policyCode) {
        TrafficPolicyPo po = mapper.selectOne(new LambdaQueryWrapper<TrafficPolicyPo>()
                .eq(TrafficPolicyPo::getPolicyCode, policyCode)
                .eq(TrafficPolicyPo::getRowValid, true));
        return Optional.ofNullable(po).map(this::toDomain);
    }

    public Optional<TrafficPolicy> findAny(String policyCode) {
        return Optional.ofNullable(mapper.selectOne(new LambdaQueryWrapper<TrafficPolicyPo>()
                .eq(TrafficPolicyPo::getPolicyCode, policyCode))).map(this::toDomain);
    }

    public void insert(TrafficPolicy policy, String actor) {
        Date now = new Date();
        TrafficPolicyPo po = TrafficPolicyPo.builder()
                .policyCode(policy.getPolicyCode())
                .policyName(policy.getPolicyName())
                .description(policy.getDescription())
                .connectTimeoutMillis(policy.getConnectTimeoutMillis())
                .responseTimeoutMillis(policy.getResponseTimeoutMillis())
                .rateLimitsJson(Json.write(policy.normalized().getRateLimits()))
                .maxConcurrentRequests(policy.getMaxConcurrentRequests())
                .circuitBreakerJson(policy.getCircuitBreaker() == null ? null : Json.write(policy.getCircuitBreaker()))
                .retryJson(policy.getRetry() == null ? null : Json.write(policy.getRetry().normalized()))
                .enabled(Boolean.TRUE.equals(policy.getEnabled()))
                .rowVersion(1)
                .rowValid(true)
                .createBy(actor)
                .createTime(now)
                .modifyBy(actor)
                .modifyTime(now)
                .build();
        mapper.insert(po);
        policy.setRowVersion(1);
    }

    public boolean update(TrafficPolicy policy, String actor) {
        int expected = policy.getRowVersion() == null ? 0 : policy.getRowVersion();
        policy.normalized();
        int rows = mapper.update(null, new LambdaUpdateWrapper<TrafficPolicyPo>()
                .eq(TrafficPolicyPo::getPolicyCode, policy.getPolicyCode())
                .eq(TrafficPolicyPo::getRowValid, true)
                .eq(TrafficPolicyPo::getRowVersion, expected)
                .set(TrafficPolicyPo::getPolicyName, policy.getPolicyName())
                .set(TrafficPolicyPo::getDescription, policy.getDescription())
                .set(TrafficPolicyPo::getConnectTimeoutMillis, policy.getConnectTimeoutMillis())
                .set(TrafficPolicyPo::getResponseTimeoutMillis, policy.getResponseTimeoutMillis())
                .set(TrafficPolicyPo::getRateLimitsJson, Json.write(policy.getRateLimits()))
                .set(TrafficPolicyPo::getMaxConcurrentRequests, policy.getMaxConcurrentRequests())
                .set(TrafficPolicyPo::getCircuitBreakerJson, policy.getCircuitBreaker() == null ? null : Json.write(policy.getCircuitBreaker()))
                .set(TrafficPolicyPo::getRetryJson, policy.getRetry() == null ? null : Json.write(policy.getRetry()))
                .set(TrafficPolicyPo::getEnabled, Boolean.TRUE.equals(policy.getEnabled()))
                .set(TrafficPolicyPo::getModifyBy, actor)
                .set(TrafficPolicyPo::getModifyTime, new Date())
                .set(TrafficPolicyPo::getRowVersion, expected + 1));
        if (rows > 0) {
            policy.setRowVersion(expected + 1);
        }
        return rows > 0;
    }

    public boolean logicalDelete(String policyCode, String actor) {
        int rows = mapper.update(null, new LambdaUpdateWrapper<TrafficPolicyPo>()
                .eq(TrafficPolicyPo::getPolicyCode, policyCode)
                .eq(TrafficPolicyPo::getRowValid, true)
                .set(TrafficPolicyPo::getRowValid, false)
                .set(TrafficPolicyPo::getModifyBy, actor)
                .set(TrafficPolicyPo::getModifyTime, new Date())
                .setSql("row_version = row_version + 1"));
        return rows > 0;
    }

    private TrafficPolicy toDomain(TrafficPolicyPo po) {
        TrafficPolicy policy = TrafficPolicy.builder()
                .policyCode(po.getPolicyCode())
                .policyName(po.getPolicyName())
                .description(po.getDescription())
                .connectTimeoutMillis(po.getConnectTimeoutMillis())
                .responseTimeoutMillis(po.getResponseTimeoutMillis())
                .rateLimits(StringUtils.hasText(po.getRateLimitsJson())
                        ? Json.readList(po.getRateLimitsJson(), RateLimitRule.class) : new java.util.ArrayList<>())
                .maxConcurrentRequests(po.getMaxConcurrentRequests())
                .circuitBreaker(StringUtils.hasText(po.getCircuitBreakerJson())
                        ? Json.read(po.getCircuitBreakerJson(), CircuitBreakerRule.class) : null)
                .retry(StringUtils.hasText(po.getRetryJson())
                        ? Json.read(po.getRetryJson(), RetryRule.class) : null)
                .enabled(po.getEnabled())
                .rowVersion(po.getRowVersion())
                .build();
        return policy.normalized();
    }

}
