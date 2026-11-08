package net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.LambdaUpdateWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;
import net.hwyz.iov.cloud.edd.sgw.common.PageSlice;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.mapper.AuthPolicyMapper;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.po.AuthPolicyPo;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * 认证授权策略草稿仓储。
 *
 * @author hwyz_leo
 */
@Repository
public class AuthPolicyRepository {

    private final AuthPolicyMapper mapper;

    public AuthPolicyRepository(AuthPolicyMapper mapper) {
        this.mapper = mapper;
    }

    public PageSlice<AuthPolicy> page(int page, int size, String name, Boolean enabled) {
        LambdaQueryWrapper<AuthPolicyPo> wrapper = new LambdaQueryWrapper<AuthPolicyPo>()
                .eq(AuthPolicyPo::getRowValid, true)
                .like(StringUtils.hasText(name), AuthPolicyPo::getPolicyName, name)
                .eq(enabled != null, AuthPolicyPo::getEnabled, enabled)
                .orderByAsc(AuthPolicyPo::getPolicyCode);
        Page<AuthPolicyPo> result = mapper.selectPage(new Page<>(page, size), wrapper);
        return new PageSlice<>(result.getRecords().stream().map(this::toDomain).toList(),
                result.getTotal(), page, size);
    }

    public List<AuthPolicy> findAllValid() {
        return mapper.selectList(new LambdaQueryWrapper<AuthPolicyPo>()
                        .eq(AuthPolicyPo::getRowValid, true)
                        .orderByAsc(AuthPolicyPo::getPolicyCode))
                .stream().map(this::toDomain).toList();
    }

    public Optional<AuthPolicy> findValid(String policyCode) {
        AuthPolicyPo po = mapper.selectOne(new LambdaQueryWrapper<AuthPolicyPo>()
                .eq(AuthPolicyPo::getPolicyCode, policyCode)
                .eq(AuthPolicyPo::getRowValid, true));
        return Optional.ofNullable(po).map(this::toDomain);
    }

    public Optional<AuthPolicy> findAny(String policyCode) {
        return Optional.ofNullable(mapper.selectOne(new LambdaQueryWrapper<AuthPolicyPo>()
                .eq(AuthPolicyPo::getPolicyCode, policyCode))).map(this::toDomain);
    }

    public void insert(AuthPolicy policy, String actor) {
        Date now = new Date();
        AuthPolicyPo po = AuthPolicyPo.builder()
                .policyCode(policy.getPolicyCode())
                .policyName(policy.getPolicyName())
                .description(policy.getDescription())
                .accessMode(policy.getAccessMode() == null ? null : policy.getAccessMode().name())
                .allowedClientTypes(join(policy.getAllowedClientTypes()))
                .requiredScopes(join(policy.getRequiredScopes()))
                .requiredPermissions(join(policy.getRequiredPermissions()))
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

    public boolean update(AuthPolicy policy, String actor) {
        int expected = policy.getRowVersion() == null ? 0 : policy.getRowVersion();
        int rows = mapper.update(null, new LambdaUpdateWrapper<AuthPolicyPo>()
                .eq(AuthPolicyPo::getPolicyCode, policy.getPolicyCode())
                .eq(AuthPolicyPo::getRowValid, true)
                .eq(AuthPolicyPo::getRowVersion, expected)
                .set(AuthPolicyPo::getPolicyName, policy.getPolicyName())
                .set(AuthPolicyPo::getDescription, policy.getDescription())
                .set(AuthPolicyPo::getAccessMode, policy.getAccessMode() == null ? null : policy.getAccessMode().name())
                .set(AuthPolicyPo::getAllowedClientTypes, join(policy.getAllowedClientTypes()))
                .set(AuthPolicyPo::getRequiredScopes, join(policy.getRequiredScopes()))
                .set(AuthPolicyPo::getRequiredPermissions, join(policy.getRequiredPermissions()))
                .set(AuthPolicyPo::getEnabled, Boolean.TRUE.equals(policy.getEnabled()))
                .set(AuthPolicyPo::getModifyBy, actor)
                .set(AuthPolicyPo::getModifyTime, new Date())
                .set(AuthPolicyPo::getRowVersion, expected + 1));
        if (rows > 0) {
            policy.setRowVersion(expected + 1);
        }
        return rows > 0;
    }

    public boolean logicalDelete(String policyCode, String actor) {
        int rows = mapper.update(null, new LambdaUpdateWrapper<AuthPolicyPo>()
                .eq(AuthPolicyPo::getPolicyCode, policyCode)
                .eq(AuthPolicyPo::getRowValid, true)
                .set(AuthPolicyPo::getRowValid, false)
                .set(AuthPolicyPo::getModifyBy, actor)
                .set(AuthPolicyPo::getModifyTime, new Date())
                .setSql("row_version = row_version + 1"));
        return rows > 0;
    }

    private AuthPolicy toDomain(AuthPolicyPo po) {
        return AuthPolicy.builder()
                .policyCode(po.getPolicyCode())
                .policyName(po.getPolicyName())
                .description(po.getDescription())
                .accessMode(po.getAccessMode() == null ? null : AccessMode.valueOf(po.getAccessMode()))
                .allowedClientTypes(split(po.getAllowedClientTypes()))
                .requiredScopes(split(po.getRequiredScopes()))
                .requiredPermissions(split(po.getRequiredPermissions()))
                .enabled(po.getEnabled())
                .rowVersion(po.getRowVersion())
                .build();
    }

    static String join(List<String> values) {
        return values == null || values.isEmpty() ? null : String.join(",", values);
    }

    static List<String> split(String value) {
        return StringUtils.hasText(value) ? Arrays.stream(value.split(","))
                .map(String::trim).filter(item -> !item.isEmpty()).toList() : new java.util.ArrayList<>();
    }

}
