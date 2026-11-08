package net.hwyz.iov.cloud.edd.sgw.application;

import net.hwyz.iov.cloud.edd.sgw.api.vo.request.CopyRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.request.RouteSaveRequest;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.RouteResponse;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ValidationErrorVo;
import net.hwyz.iov.cloud.edd.sgw.api.vo.response.ValidationResultVo;
import net.hwyz.iov.cloud.edd.sgw.common.PageSlice;
import net.hwyz.iov.cloud.edd.sgw.common.SgwErrorCode;
import net.hwyz.iov.cloud.edd.sgw.common.SgwException;
import net.hwyz.iov.cloud.edd.sgw.config.SgwProperties;
import net.hwyz.iov.cloud.edd.sgw.domain.model.RouteDefinition;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.PolicyValidator;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.RouteValidator;
import net.hwyz.iov.cloud.edd.sgw.domain.validation.ValidationResult;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.AuthPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.CanaryPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.RouteRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.TrafficPolicyRepository;
import net.hwyz.iov.cloud.edd.sgw.infrastructure.persistence.repository.WorkspaceRepository;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 路由管理用例。
 *
 * @author hwyz_leo
 */
@Service
public class RouteAdminService {

    private final RouteRepository routeRepository;

    private final AuthPolicyRepository authPolicyRepository;

    private final TrafficPolicyRepository trafficPolicyRepository;

    private final CanaryPolicyRepository canaryPolicyRepository;

    private final WorkspaceRepository workspaceRepository;

    private final RouteValidator routeValidator;

    private final PolicyValidator policyValidator;

    private final AuditService auditService;

    private final SgwProperties properties;

    public RouteAdminService(RouteRepository routeRepository, AuthPolicyRepository authPolicyRepository,
                             TrafficPolicyRepository trafficPolicyRepository,
                             CanaryPolicyRepository canaryPolicyRepository, WorkspaceRepository workspaceRepository,
                             RouteValidator routeValidator, PolicyValidator policyValidator,
                             AuditService auditService, SgwProperties properties) {
        this.routeRepository = routeRepository;
        this.authPolicyRepository = authPolicyRepository;
        this.trafficPolicyRepository = trafficPolicyRepository;
        this.canaryPolicyRepository = canaryPolicyRepository;
        this.workspaceRepository = workspaceRepository;
        this.routeValidator = routeValidator;
        this.policyValidator = policyValidator;
        this.auditService = auditService;
        this.properties = properties;
    }

    /**
     * 物理分页查询
     *
     * @param page       页码
     * @param size       每页条数
     * @param name       名称
     * @param enabled    启用状态
     * @param target     目标
     * @param clientType 客户端类型
     * @return 分页结果
     */
    public PageSlice<RouteResponse> page(int page, int size, String name, Boolean enabled,
                                         String target, String clientType) {
        PageSlice<RouteDefinition> slice = routeRepository.page(page, size, name, enabled, target, clientType);
        return new PageSlice<>(slice.items().stream().map(Assembler::toResponse).toList(),
                slice.total(), slice.page(), slice.size());
    }

    /**
     * 查询路由详情
     *
     * @param routeCode 编码
     * @return 路由
     */
    public RouteDefinition get(String routeCode) {
        return routeRepository.findValid(routeCode)
                .orElseThrow(() -> new SgwException(SgwErrorCode.ROUTE_NOT_FOUND, "路由不存在: " + routeCode));
    }

    /**
     * 新增路由草稿
     *
     * @param request 请求
     * @param context 上下文
     * @return 路由
     */
    public RouteDefinition create(RouteSaveRequest request, AdminContext context) {
        RouteDefinition route = Assembler.toDomain(request);
        validateOrThrow(route);
        if (routeRepository.findAny(route.getRouteCode()).isPresent()) {
            throw new SgwException(SgwErrorCode.CONFLICT, "路由编码已存在且不可复用: " + route.getRouteCode());
        }
        return auditService.run("CREATE", "ROUTE", route.getRouteCode(), null, context, () -> {
            routeRepository.insert(route, context.actor());
            workspaceRepository.bumpDraftRevision(context.actor());
            return AuditService.Audited.of(route, Assembler.toResponse(route));
        });
    }

    /**
     * 乐观更新路由草稿
     *
     * @param routeCode 编码
     * @param request   请求
     * @param context   上下文
     * @return 路由
     */
    public RouteDefinition update(String routeCode, RouteSaveRequest request, AdminContext context) {
        RouteDefinition existing = get(routeCode);
        RouteDefinition route = Assembler.toDomain(request);
        route.setRouteCode(routeCode);
        if (request.getRowVersion() == null) {
            throw new SgwException(SgwErrorCode.VALIDATION_FAILED, "更新路由必须携带 rowVersion");
        }
        route.setRowVersion(request.getRowVersion());
        validateOrThrow(route);
        return auditService.run("UPDATE", "ROUTE", routeCode, Assembler.toResponse(existing), context, () -> {
            if (!routeRepository.update(route, context.actor())) {
                throw new SgwException(SgwErrorCode.CONFLICT, "路由已被其他操作修改，请刷新后重试");
            }
            workspaceRepository.bumpDraftRevision(context.actor());
            return AuditService.Audited.of(route, Assembler.toResponse(route));
        });
    }

    /**
     * 复制路由草稿
     *
     * @param routeCode 源编码
     * @param request   复制请求
     * @param context   上下文
     * @return 新路由
     */
    public RouteDefinition copy(String routeCode, CopyRequest request, AdminContext context) {
        RouteDefinition source = get(routeCode);
        RouteDefinition copy = copyOf(source, request.getNewCode(), request.getNewName());
        validateOrThrow(copy);
        if (routeRepository.findAny(copy.getRouteCode()).isPresent()) {
            throw new SgwException(SgwErrorCode.CONFLICT, "路由编码已存在且不可复用: " + copy.getRouteCode());
        }
        return auditService.run("COPY", "ROUTE", copy.getRouteCode(), Assembler.toResponse(source), context, () -> {
            routeRepository.insert(copy, context.actor());
            workspaceRepository.bumpDraftRevision(context.actor());
            return AuditService.Audited.of(copy, Assembler.toResponse(copy));
        });
    }

    /**
     * 逻辑删除路由草稿
     *
     * @param routeCode 编码
     * @param context   上下文
     */
    public void delete(String routeCode, AdminContext context) {
        RouteDefinition existing = get(routeCode);
        auditService.run("DELETE", "ROUTE", routeCode, Assembler.toResponse(existing), context, () -> {
            if (!routeRepository.logicalDelete(routeCode, context.actor())) {
                throw new SgwException(SgwErrorCode.CONFLICT, "路由已被删除或状态已变化");
            }
            workspaceRepository.bumpDraftRevision(context.actor());
            return AuditService.Audited.of(null, null);
        });
    }

    /**
     * 校验路由配置
     *
     * @param request 请求
     * @return 校验结果
     */
    public ValidationResultVo validate(RouteSaveRequest request) {
        RouteDefinition route = Assembler.toDomain(request);
        ValidationResult result = routeValidator.validate(route, properties.getRuntime().allowedDirectHosts());
        checkPolicyReferences(route, result);
        return toVo(result);
    }

    private void checkPolicyReferences(RouteDefinition route, ValidationResult result) {
        if (route.getAuthPolicyCode() != null) {
            authPolicyRepository.findValid(route.getAuthPolicyCode())
                    .ifPresentOrElse(policy -> result.merge(policyValidator.validateAuth(policy)),
                            () -> result.add("authPolicyCode", "引用的认证授权策略不存在"));
        }
        if (route.getTrafficPolicyCode() != null) {
            trafficPolicyRepository.findValid(route.getTrafficPolicyCode())
                    .ifPresentOrElse(policy -> result.merge(policyValidator.validateTraffic(policy)),
                            () -> result.add("trafficPolicyCode", "引用的流量治理策略不存在"));
        }
        if (route.getCanaryPolicyCode() != null) {
            canaryPolicyRepository.findValid(route.getCanaryPolicyCode())
                    .ifPresentOrElse(policy -> result.merge(policyValidator.validateCanary(
                                    policy, properties.getRuntime().allowedDirectHosts())),
                            () -> result.add("canaryPolicyCode", "引用的灰度策略不存在"));
        }
    }

    private void validateOrThrow(RouteDefinition route) {
        ValidationResult result = routeValidator.validate(route, properties.getRuntime().allowedDirectHosts());
        checkPolicyReferences(route, result);
        result.throwIfInvalid(SgwErrorCode.VALIDATION_FAILED);
    }

    private RouteDefinition copyOf(RouteDefinition source, String newCode, String newName) {
        return RouteDefinition.builder()
                .routeCode(newCode)
                .routeName(newName == null || newName.isBlank()
                        ? source.getRouteName() + " 副本" : newName)
                .description(source.getDescription())
                .priority(source.getPriority())
                .enabled(source.getEnabled())
                .match(source.getMatch())
                .target(source.getTarget())
                .transform(source.getTransform())
                .authPolicyCode(source.getAuthPolicyCode())
                .trafficPolicyCode(source.getTrafficPolicyCode())
                .canaryPolicyCode(source.getCanaryPolicyCode())
                .build();
    }

    /**
     * 校验结果转 VO
     *
     * @param result 校验结果
     * @return VO
     */
    public static ValidationResultVo toVo(ValidationResult result) {
        List<ValidationErrorVo> errors = result.errors().stream()
                .map(error -> ValidationErrorVo.builder()
                        .field(error.field())
                        .message(error.message())
                        .build())
                .toList();
        return ValidationResultVo.builder().valid(result.valid()).errors(errors).build();
    }

}
