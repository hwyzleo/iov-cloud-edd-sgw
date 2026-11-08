package net.hwyz.iov.cloud.edd.sgw.application;

import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;
import net.hwyz.iov.cloud.edd.sgw.api.enums.PolicyType;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.AuthPolicySaveRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.CanaryPolicySaveRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.CopyRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.TrafficPolicySaveRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ValidationResultVo;
import net.hwyz.iov.cloud.edd.sgw.common.PageSlice;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import net.hwyz.iov.cloud.edd.sgw.domain.model.AuthPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.CanaryPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.model.TrafficPolicy;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.PolicyValidator;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.ValidationResult;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.AuthPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.CanaryPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.RouteRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.TrafficPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.WorkspaceRepository;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 治理策略管理用例。
 *
 * @author hwyz_leo
 */
@Service
public class PolicyAdminService {

    private final AuthPolicyRepository authPolicyRepository;

    private final TrafficPolicyRepository trafficPolicyRepository;

    private final CanaryPolicyRepository canaryPolicyRepository;

    private final RouteRepository routeRepository;

    private final WorkspaceRepository workspaceRepository;

    private final PolicyValidator policyValidator;

    private final AuditService auditService;

    private final SgwProperties properties;

    public PolicyAdminService(AuthPolicyRepository authPolicyRepository, TrafficPolicyRepository trafficPolicyRepository,
                              CanaryPolicyRepository canaryPolicyRepository, RouteRepository routeRepository,
                              WorkspaceRepository workspaceRepository, PolicyValidator policyValidator,
                              AuditService auditService, SgwProperties properties) {
        this.authPolicyRepository = authPolicyRepository;
        this.trafficPolicyRepository = trafficPolicyRepository;
        this.canaryPolicyRepository = canaryPolicyRepository;
        this.routeRepository = routeRepository;
        this.workspaceRepository = workspaceRepository;
        this.policyValidator = policyValidator;
        this.auditService = auditService;
        this.properties = properties;
    }

    public PageSlice<Object> page(String type, int page, int size, String name, Boolean enabled) {
        return switch (requireType(type)) {
            case AUTH -> {
                PageSlice<AuthPolicy> slice = authPolicyRepository.page(page, size, name, enabled);
                yield new PageSlice<Object>(java.util.List.copyOf(slice.items().stream()
                        .map(Assembler::toResponse).toList()), slice.total(), slice.page(), slice.size());
            }
            case TRAFFIC -> {
                PageSlice<TrafficPolicy> slice = trafficPolicyRepository.page(page, size, name, enabled);
                yield new PageSlice<Object>(java.util.List.copyOf(slice.items().stream()
                        .map(Assembler::toResponse).toList()), slice.total(), slice.page(), slice.size());
            }
            case CANARY -> {
                PageSlice<CanaryPolicy> slice = canaryPolicyRepository.page(page, size, name, enabled);
                yield new PageSlice<Object>(java.util.List.copyOf(slice.items().stream()
                        .map(Assembler::toResponse).toList()), slice.total(), slice.page(), slice.size());
            }
        };
    }

    public Object get(String type, String policyCode) {
        return switch (requireType(type)) {
            case AUTH -> Assembler.toResponse(authPolicyRepository.findValid(policyCode)
                    .orElseThrow(() -> notFound("认证授权策略", policyCode)));
            case TRAFFIC -> Assembler.toResponse(trafficPolicyRepository.findValid(policyCode)
                    .orElseThrow(() -> notFound("流量治理策略", policyCode)));
            case CANARY -> Assembler.toResponse(canaryPolicyRepository.findValid(policyCode)
                    .orElseThrow(() -> notFound("灰度策略", policyCode)));
        };
    }

    public Object create(String type, Object request, AdminContext context) {
        PolicyType policyType = requireType(type);
        return switch (policyType) {
            case AUTH -> createAuth((AuthPolicySaveRequest) request, context);
            case TRAFFIC -> createTraffic((TrafficPolicySaveRequest) request, context);
            case CANARY -> createCanary((CanaryPolicySaveRequest) request, context);
        };
    }

    public Object update(String type, String policyCode, Object request, AdminContext context) {
        return switch (requireType(type)) {
            case AUTH -> updateAuth(policyCode, (AuthPolicySaveRequest) request, context);
            case TRAFFIC -> updateTraffic(policyCode, (TrafficPolicySaveRequest) request, context);
            case CANARY -> updateCanary(policyCode, (CanaryPolicySaveRequest) request, context);
        };
    }

    public Object copy(String type, String policyCode, CopyRequest request, AdminContext context) {
        return switch (requireType(type)) {
            case AUTH -> copyAuth(policyCode, request, context);
            case TRAFFIC -> copyTraffic(policyCode, request, context);
            case CANARY -> copyCanary(policyCode, request, context);
        };
    }

    public void delete(String type, String policyCode, AdminContext context) {
        PolicyType policyType = requireType(type);
        List<String> references = routeRepository.findRouteCodesReferencing(policyType.value(), policyCode);
        if (!references.isEmpty()) {
            throw new SgwException(SgwErrorCode.POLICY_REFERENCED,
                    "策略仍被路由引用: " + String.join(",", references));
        }
        switch (policyType) {
            case AUTH -> {
                AuthPolicy existing = authPolicyRepository.findValid(policyCode)
                        .orElseThrow(() -> notFound("认证授权策略", policyCode));
                audit("DELETE", "AUTH_POLICY", policyCode, Assembler.toResponse(existing), context,
                        () -> authPolicyRepository.logicalDelete(policyCode, context.actor()));
            }
            case TRAFFIC -> {
                TrafficPolicy existing = trafficPolicyRepository.findValid(policyCode)
                        .orElseThrow(() -> notFound("流量治理策略", policyCode));
                audit("DELETE", "TRAFFIC_POLICY", policyCode, Assembler.toResponse(existing), context,
                        () -> trafficPolicyRepository.logicalDelete(policyCode, context.actor()));
            }
            case CANARY -> {
                CanaryPolicy existing = canaryPolicyRepository.findValid(policyCode)
                        .orElseThrow(() -> notFound("灰度策略", policyCode));
                audit("DELETE", "CANARY_POLICY", policyCode, Assembler.toResponse(existing), context,
                        () -> canaryPolicyRepository.logicalDelete(policyCode, context.actor()));
            }
        }
    }

    public ValidationResultVo validate(String type, Object request) {
        ValidationResult result = switch (requireType(type)) {
            case AUTH -> policyValidator.validateAuth((AuthPolicy) Assembler.toDomain((AuthPolicySaveRequest) request));
            case TRAFFIC -> policyValidator.validateTraffic((TrafficPolicy) Assembler.toDomain((TrafficPolicySaveRequest) request));
            case CANARY -> {
                CanaryPolicy policy = Assembler.toDomain((CanaryPolicySaveRequest) request);
                ValidationResult canaryResult = policyValidator.validateCanary(policy,
                        properties.getRuntime().allowedDirectHosts());
                checkCanaryReferences(policy, canaryResult);
                yield canaryResult;
            }
        };
        return RouteAdminService.toVo(result);
    }

    private void checkCanaryReferences(CanaryPolicy policy, ValidationResult result) {
        if (policy.getStableKey() == null) {
            return;
        }
        List<RouteDefinition> routes = routeRepository.findAllValid();
        for (RouteDefinition route : routes) {
            if (!route.effective() || !policy.getPolicyCode().equals(route.getCanaryPolicyCode())) {
                continue;
            }
            AccessMode mode = AccessMode.ANONYMOUS;
            if (route.getAuthPolicyCode() != null) {
                AuthPolicy auth = authPolicyRepository.findValid(route.getAuthPolicyCode()).orElse(null);
                if (auth != null && auth.getAccessMode() != null) {
                    mode = auth.getAccessMode();
                }
            }
            List<String> unavailable = policyValidator.unavailableStableKeys(policy, mode);
            if (!unavailable.isEmpty()) {
                result.add("stableKey", "灰度稳定键 " + unavailable.get(0)
                        + " 在路由 " + route.getRouteCode() + " 的 " + mode + " 访问模式下不可用");
            }
        }
    }

    private AuthPolicy createAuth(AuthPolicySaveRequest request, AdminContext context) {
        AuthPolicy policy = Assembler.toDomain(request);
        validateAuthOrThrow(policy);
        if (authPolicyRepository.findAny(policy.getPolicyCode()).isPresent()) {
            throw new SgwException(SgwErrorCode.CONFLICT, "策略编码已存在且不可复用: " + policy.getPolicyCode());
        }
        return auditService.run("CREATE", "AUTH_POLICY", policy.getPolicyCode(), null, context, () -> {
            authPolicyRepository.insert(policy, context.actor());
            workspaceRepository.bumpDraftRevision(context.actor());
            return AuditService.Audited.of(policy, Assembler.toResponse(policy));
        });
    }

    private AuthPolicy updateAuth(String code, AuthPolicySaveRequest request, AdminContext context) {
        AuthPolicy existing = authPolicyRepository.findValid(code)
                .orElseThrow(() -> notFound("认证授权策略", code));
        AuthPolicy policy = Assembler.toDomain(request);
        policy.setPolicyCode(code);
        policy.setRowVersion(request.getRowVersion());
        if (request.getRowVersion() == null) {
            throw new SgwException(SgwErrorCode.VALIDATION_FAILED, "更新策略必须携带 rowVersion");
        }
        validateAuthOrThrow(policy);
        return auditService.run("UPDATE", "AUTH_POLICY", code, Assembler.toResponse(existing), context, () -> {
            if (!authPolicyRepository.update(policy, context.actor())) {
                throw new SgwException(SgwErrorCode.CONFLICT, "策略已被其他操作修改，请刷新后重试");
            }
            workspaceRepository.bumpDraftRevision(context.actor());
            return AuditService.Audited.of(policy, Assembler.toResponse(policy));
        });
    }

    private AuthPolicy copyAuth(String code, CopyRequest request, AdminContext context) {
        AuthPolicy source = authPolicyRepository.findValid(code).orElseThrow(() -> notFound("认证授权策略", code));
        AuthPolicy copy = AuthPolicy.builder()
                .policyCode(request.getNewCode())
                .policyName(request.getNewName() == null || request.getNewName().isBlank()
                        ? source.getPolicyName() + " 副本" : request.getNewName())
                .description(source.getDescription())
                .accessMode(source.getAccessMode())
                .allowedClientTypes(source.getAllowedClientTypes())
                .requiredScopes(source.getRequiredScopes())
                .requiredPermissions(source.getRequiredPermissions())
                .enabled(source.getEnabled())
                .build();
        validateAuthOrThrow(copy);
        if (authPolicyRepository.findAny(copy.getPolicyCode()).isPresent()) {
            throw new SgwException(SgwErrorCode.CONFLICT, "策略编码已存在且不可复用: " + copy.getPolicyCode());
        }
        return auditService.run("COPY", "AUTH_POLICY", copy.getPolicyCode(), Assembler.toResponse(source), context, () -> {
            authPolicyRepository.insert(copy, context.actor());
            workspaceRepository.bumpDraftRevision(context.actor());
            return AuditService.Audited.of(copy, Assembler.toResponse(copy));
        });
    }

    private TrafficPolicy createTraffic(TrafficPolicySaveRequest request, AdminContext context) {
        TrafficPolicy policy = Assembler.toDomain(request);
        validateTrafficOrThrow(policy);
        if (trafficPolicyRepository.findAny(policy.getPolicyCode()).isPresent()) {
            throw new SgwException(SgwErrorCode.CONFLICT, "策略编码已存在且不可复用: " + policy.getPolicyCode());
        }
        return auditService.run("CREATE", "TRAFFIC_POLICY", policy.getPolicyCode(), null, context, () -> {
            trafficPolicyRepository.insert(policy, context.actor());
            workspaceRepository.bumpDraftRevision(context.actor());
            return AuditService.Audited.of(policy, Assembler.toResponse(policy));
        });
    }

    private TrafficPolicy updateTraffic(String code, TrafficPolicySaveRequest request, AdminContext context) {
        TrafficPolicy existing = trafficPolicyRepository.findValid(code)
                .orElseThrow(() -> notFound("流量治理策略", code));
        TrafficPolicy policy = Assembler.toDomain(request);
        policy.setPolicyCode(code);
        policy.setRowVersion(request.getRowVersion());
        if (request.getRowVersion() == null) {
            throw new SgwException(SgwErrorCode.VALIDATION_FAILED, "更新策略必须携带 rowVersion");
        }
        validateTrafficOrThrow(policy);
        return auditService.run("UPDATE", "TRAFFIC_POLICY", code, Assembler.toResponse(existing), context, () -> {
            if (!trafficPolicyRepository.update(policy, context.actor())) {
                throw new SgwException(SgwErrorCode.CONFLICT, "策略已被其他操作修改，请刷新后重试");
            }
            workspaceRepository.bumpDraftRevision(context.actor());
            return AuditService.Audited.of(policy, Assembler.toResponse(policy));
        });
    }

    private TrafficPolicy copyTraffic(String code, CopyRequest request, AdminContext context) {
        TrafficPolicy source = trafficPolicyRepository.findValid(code)
                .orElseThrow(() -> notFound("流量治理策略", code));
        TrafficPolicy copy = TrafficPolicy.builder()
                .policyCode(request.getNewCode())
                .policyName(request.getNewName() == null || request.getNewName().isBlank()
                        ? source.getPolicyName() + " 副本" : request.getNewName())
                .description(source.getDescription())
                .connectTimeoutMillis(source.getConnectTimeoutMillis())
                .responseTimeoutMillis(source.getResponseTimeoutMillis())
                .rateLimits(source.getRateLimits())
                .maxConcurrentRequests(source.getMaxConcurrentRequests())
                .circuitBreaker(source.getCircuitBreaker())
                .retry(source.getRetry())
                .enabled(source.getEnabled())
                .build();
        validateTrafficOrThrow(copy);
        if (trafficPolicyRepository.findAny(copy.getPolicyCode()).isPresent()) {
            throw new SgwException(SgwErrorCode.CONFLICT, "策略编码已存在且不可复用: " + copy.getPolicyCode());
        }
        return auditService.run("COPY", "TRAFFIC_POLICY", copy.getPolicyCode(), Assembler.toResponse(source), context, () -> {
            trafficPolicyRepository.insert(copy, context.actor());
            workspaceRepository.bumpDraftRevision(context.actor());
            return AuditService.Audited.of(copy, Assembler.toResponse(copy));
        });
    }

    private CanaryPolicy createCanary(CanaryPolicySaveRequest request, AdminContext context) {
        CanaryPolicy policy = Assembler.toDomain(request);
        validateCanaryOrThrow(policy);
        if (canaryPolicyRepository.findAny(policy.getPolicyCode()).isPresent()) {
            throw new SgwException(SgwErrorCode.CONFLICT, "策略编码已存在且不可复用: " + policy.getPolicyCode());
        }
        return auditService.run("CREATE", "CANARY_POLICY", policy.getPolicyCode(), null, context, () -> {
            canaryPolicyRepository.insert(policy, context.actor());
            workspaceRepository.bumpDraftRevision(context.actor());
            return AuditService.Audited.of(policy, Assembler.toResponse(policy));
        });
    }

    private CanaryPolicy updateCanary(String code, CanaryPolicySaveRequest request, AdminContext context) {
        CanaryPolicy existing = canaryPolicyRepository.findValid(code).orElseThrow(() -> notFound("灰度策略", code));
        CanaryPolicy policy = Assembler.toDomain(request);
        policy.setPolicyCode(code);
        policy.setRowVersion(request.getRowVersion());
        if (request.getRowVersion() == null) {
            throw new SgwException(SgwErrorCode.VALIDATION_FAILED, "更新策略必须携带 rowVersion");
        }
        validateCanaryOrThrow(policy);
        return auditService.run("UPDATE", "CANARY_POLICY", code, Assembler.toResponse(existing), context, () -> {
            if (!canaryPolicyRepository.update(policy, context.actor())) {
                throw new SgwException(SgwErrorCode.CONFLICT, "策略已被其他操作修改，请刷新后重试");
            }
            workspaceRepository.bumpDraftRevision(context.actor());
            return AuditService.Audited.of(policy, Assembler.toResponse(policy));
        });
    }

    private CanaryPolicy copyCanary(String code, CopyRequest request, AdminContext context) {
        CanaryPolicy source = canaryPolicyRepository.findValid(code).orElseThrow(() -> notFound("灰度策略", code));
        CanaryPolicy copy = CanaryPolicy.builder()
                .policyCode(request.getNewCode())
                .policyName(request.getNewName() == null || request.getNewName().isBlank()
                        ? source.getPolicyName() + " 副本" : request.getNewName())
                .description(source.getDescription())
                .stableKey(source.getStableKey())
                .rules(source.getRules())
                .enabled(source.getEnabled())
                .build();
        validateCanaryOrThrow(copy);
        if (canaryPolicyRepository.findAny(copy.getPolicyCode()).isPresent()) {
            throw new SgwException(SgwErrorCode.CONFLICT, "策略编码已存在且不可复用: " + copy.getPolicyCode());
        }
        return auditService.run("COPY", "CANARY_POLICY", copy.getPolicyCode(), Assembler.toResponse(source), context, () -> {
            canaryPolicyRepository.insert(copy, context.actor());
            workspaceRepository.bumpDraftRevision(context.actor());
            return AuditService.Audited.of(copy, Assembler.toResponse(copy));
        });
    }

    private void validateAuthOrThrow(AuthPolicy policy) {
        policyValidator.validateAuth(policy).throwIfInvalid(SgwErrorCode.VALIDATION_FAILED);
    }

    private void validateTrafficOrThrow(TrafficPolicy policy) {
        policyValidator.validateTraffic(policy).throwIfInvalid(SgwErrorCode.VALIDATION_FAILED);
    }

    private void validateCanaryOrThrow(CanaryPolicy policy) {
        policyValidator.validateCanary(policy, properties.getRuntime().allowedDirectHosts())
                .throwIfInvalid(SgwErrorCode.VALIDATION_FAILED);
    }

    private void audit(String action, String objectType, String objectCode, Object before, AdminContext context,
                       java.util.concurrent.Callable<Boolean> action0) {
        auditService.run(action, objectType, objectCode, before, context, () -> {
            try {
                if (!Boolean.TRUE.equals(action0.call())) {
                    throw new SgwException(SgwErrorCode.CONFLICT, "策略不存在或状态已变化");
                }
                workspaceRepository.bumpDraftRevision(context.actor());
                return AuditService.Audited.of(null, null);
            } catch (SgwException e) {
                throw e;
            } catch (Exception e) {
                throw new SgwException(SgwErrorCode.CONFLICT, "策略删除失败", e);
            }
        });
    }

    private PolicyType requireType(String type) {
        PolicyType policyType = PolicyType.valOf(type);
        if (policyType == null) {
            throw new SgwException(SgwErrorCode.VALIDATION_FAILED, "未知策略类型: " + type);
        }
        return policyType;
    }

    private SgwException notFound(String name, String code) {
        return new SgwException(SgwErrorCode.ROUTE_NOT_FOUND, name + "不存在: " + code);
    }

}
