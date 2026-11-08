package net.hwyz.iov.cloud.edd.sgw.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

/**
 * 灰度规则条件。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CanaryConditions {

    private List<String> clientTypes;

    private List<String> userIds;

    private List<String> vehicleIds;

    private List<HeaderMatch> headers;

    /**
     * 归一化集合字段
     *
     * @return 自身
     */
    public CanaryConditions normalized() {
        clientTypes = clientTypes == null ? new ArrayList<>() : clientTypes;
        userIds = userIds == null ? new ArrayList<>() : userIds;
        vehicleIds = vehicleIds == null ? new ArrayList<>() : vehicleIds;
        headers = headers == null ? new ArrayList<>() : headers;
        return this;
    }

}
