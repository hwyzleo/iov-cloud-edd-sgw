package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.LambdaUpdateWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import net.hwyz.iov.cloud.edd.sgw.api.enums.CanaryStableKey;
import net.hwyz.iov.cloud.edd.sgw.common.Json;
import net.hwyz.iov.cloud.edd.sgw.common.PageSlice;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryRule;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper.CanaryPolicyMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.CanaryPolicyPo;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * 灰度策略草稿仓储。
 *
 * @author hwyz_leo
 */
@Repository
public class CanaryPolicyRepository {

    private final CanaryPolicyMapper mapper;

    public CanaryPolicyRepository(CanaryPolicyMapper mapper) {
        this.mapper = mapper;
    }

    public PageSlice<CanaryPolicy> page(int page, int size, String name, Boolean enabled) {
        LambdaQueryWrapper<CanaryPolicyPo> wrapper = new LambdaQueryWrapper<CanaryPolicyPo>()
                .eq(CanaryPolicyPo::getRowValid, true)
                .like(StringUtils.hasText(name), CanaryPolicyPo::getPolicyName, name)
                .eq(enabled != null, CanaryPolicyPo::getEnabled, enabled)
                .orderByAsc(CanaryPolicyPo::getPolicyCode);
        Page<CanaryPolicyPo> result = mapper.selectPage(new Page<>(page, size), wrapper);
        return new PageSlice<>(result.getRecords().stream().map(this::toDomain).toList(),
                result.getTotal(), page, size);
    }

    public List<CanaryPolicy> findAllValid() {
        return mapper.selectList(new LambdaQueryWrapper<CanaryPolicyPo>()
                        .eq(CanaryPolicyPo::getRowValid, true)
                        .orderByAsc(CanaryPolicyPo::getPolicyCode))
                .stream().map(this::toDomain).toList();
    }

    public Optional<CanaryPolicy> findValid(String policyCode) {
        CanaryPolicyPo po = mapper.selectOne(new LambdaQueryWrapper<CanaryPolicyPo>()
                .eq(CanaryPolicyPo::getPolicyCode, policyCode)
                .eq(CanaryPolicyPo::getRowValid, true));
        return Optional.ofNullable(po).map(this::toDomain);
    }

    public Optional<CanaryPolicy> findAny(String policyCode) {
        return Optional.ofNullable(mapper.selectOne(new LambdaQueryWrapper<CanaryPolicyPo>()
                .eq(CanaryPolicyPo::getPolicyCode, policyCode))).map(this::toDomain);
    }

    public void insert(CanaryPolicy policy, String actor) {
        Date now = new Date();
        CanaryPolicyPo po = CanaryPolicyPo.builder()
                .policyCode(policy.getPolicyCode())
                .policyName(policy.getPolicyName())
                .description(policy.getDescription())
                .stableKey(policy.getStableKey() == null ? null : policy.getStableKey().name())
                .rulesJson(Json.write(policy.normalized().getRules()))
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

    public boolean update(CanaryPolicy policy, String actor) {
        int expected = policy.getRowVersion() == null ? 0 : policy.getRowVersion();
        policy.normalized();
        int rows = mapper.update(null, new LambdaUpdateWrapper<CanaryPolicyPo>()
                .eq(CanaryPolicyPo::getPolicyCode, policy.getPolicyCode())
                .eq(CanaryPolicyPo::getRowValid, true)
                .eq(CanaryPolicyPo::getRowVersion, expected)
                .set(CanaryPolicyPo::getPolicyName, policy.getPolicyName())
                .set(CanaryPolicyPo::getDescription, policy.getDescription())
                .set(CanaryPolicyPo::getStableKey, policy.getStableKey() == null ? null : policy.getStableKey().name())
                .set(CanaryPolicyPo::getRulesJson, Json.write(policy.getRules()))
                .set(CanaryPolicyPo::getEnabled, Boolean.TRUE.equals(policy.getEnabled()))
                .set(CanaryPolicyPo::getModifyBy, actor)
                .set(CanaryPolicyPo::getModifyTime, new Date())
                .set(CanaryPolicyPo::getRowVersion, expected + 1));
        if (rows > 0) {
            policy.setRowVersion(expected + 1);
        }
        return rows > 0;
    }

    public boolean logicalDelete(String policyCode, String actor) {
        int rows = mapper.update(null, new LambdaUpdateWrapper<CanaryPolicyPo>()
                .eq(CanaryPolicyPo::getPolicyCode, policyCode)
                .eq(CanaryPolicyPo::getRowValid, true)
                .set(CanaryPolicyPo::getRowValid, false)
                .set(CanaryPolicyPo::getModifyBy, actor)
                .set(CanaryPolicyPo::getModifyTime, new Date())
                .setSql("row_version = row_version + 1"));
        return rows > 0;
    }

    private CanaryPolicy toDomain(CanaryPolicyPo po) {
        CanaryPolicy policy = CanaryPolicy.builder()
                .policyCode(po.getPolicyCode())
                .policyName(po.getPolicyName())
                .description(po.getDescription())
                .stableKey(StringUtils.hasText(po.getStableKey()) ? CanaryStableKey.valueOf(po.getStableKey()) : null)
                .rules(StringUtils.hasText(po.getRulesJson())
                        ? Json.readList(po.getRulesJson(), CanaryRule.class) : new java.util.ArrayList<>())
                .enabled(po.getEnabled())
                .rowVersion(po.getRowVersion())
                .build();
        return policy.normalized();
    }

}
