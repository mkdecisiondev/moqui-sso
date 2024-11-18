package org.moqui.sso

import org.moqui.context.ExecutionContext
import org.moqui.entity.EntityList
import org.moqui.entity.EntityValue
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.engine.SecurityGrantedAccessAdapter
import org.pac4j.core.profile.UserProfile

import java.sql.Timestamp

/**
 * Handles creation of Moqui user accounts.
 */
class MoquiSecurityGrantedAccessAdapter implements SecurityGrantedAccessAdapter {

    /**
     * Execution context used to access facades.
     */
    private ExecutionContext ec

    /**
     * Initializes a new {@code MoquiSecurityGrantedAccessAdapter}.
     */
    MoquiSecurityGrantedAccessAdapter(ExecutionContext ec) {
        this.ec = ec
    }

    private Map<String, Object> mapProfileFields(EntityList fieldMaps, Map attributeMap) {
        Map<String, Object> destinationMap = new HashMap<>()

        fieldMaps.forEach {
            Object srcFieldValue = ec.resource.expression(it.dstFieldExpression as String ?: it.srcFieldName as String, null, attributeMap)
            if (srcFieldValue) {
                if (it.mappingServiceRegisterId) {
                    Map<String, Object> mapFieldOut = ec.service.sync().name(it.mappingServiceRegister.serviceName as String)
                        .parameter("srcFieldValue", srcFieldValue)
                        .parameter("dstFieldName", it.dstFieldName as String)
                        .call()
                    if (mapFieldOut.destinationMap) {
                        destinationMap.putAll(mapFieldOut.destinationMap as Map)
                    }
                    if (mapFieldOut.sourceMap) {
                        destinationMap.putAll(mapFieldOut.sourceMap as Map)
                    }
                } else {
                    destinationMap.put(it.dstFieldName as String, srcFieldValue)
                }
            }
        }

        return destinationMap
    }

    @Override
    Object adapt(WebContext context, SessionStore sessionStore, Collection<UserProfile> profiles, Object... parameters) throws Exception {
        if (profiles) {
            for (UserProfile profile : profiles) {
                if (profile.username) {

                    // map profile attributes
                    Timestamp nowTimestamp = ec.user.nowTimestamp
                    EntityValue authFlow = ec.entity.find("moqui.security.sso.AuthFlow")
                            .condition("authFlowId", profile.clientName)
                            .one()
                    if ("Y" == authFlow.verboseMode) {
                        ec.logger.info("Received profile attributes: " + profile.attributes)
                    }
                    Map<String, Object> attributeMap = mapProfileFields(authFlow.fieldMaps as EntityList, profile.attributes)

                    // sync user account
                    String userId
                    String partyId
                    EntityValue userAccount = ec.entity.find("moqui.security.UserAccount")
                            .condition("username", profile.username)
                            .useCache(false)
                            .one()
                    if (userAccount) {
                        userId = userAccount.userId
                        partyId = userAccount.partyId
                        ec.service.sync().name("mantle.party.PartyServices.update#Account")
                                .parameter("userId", userId)
                                .parameter("externalUserId", profile.id)
                                .parameter("username", profile.username)
                                .parameters(attributeMap)
                                .call()
                    } else {
                        Map createAccountOut = ec.service.sync().name("mantle.party.PartyServices.create#Account")
                                .parameter("dataSourceId", authFlow.partyDataSourceId ?: "ExternalIdP")
                                .parameter("externalUserId", profile.id)
                                .parameter("username", profile.username)
                                .parameter("loginAfterCreate", false)
                                .parameters(attributeMap)
                                .call()
                        userId = createAccountOut.userId
                        partyId = createAccountOut.partyId
                    }

                    // find user groups
                    EntityList userGroupMemberList = ec.entity.find("moqui.security.UserGroupMember")
                            .condition("userId", userId)
                            .conditionDate("fromDate", "thruDate", nowTimestamp)
                            .list()
                    Set obsoleteUserGroupIdSet = new HashSet<>(userGroupMemberList*.userGroupId)

                    // find party roles
                    EntityList roleTypeList = ec.entity.find("mantle.party.PartyRole")
                            .condition("partyId", partyId)
                            .list()
                    Set obsoleteRoleTypeIdSet = new HashSet<>(roleTypeList*.roleTypeId)

                    // sync user groups and role types
                    HashSet<String> roleSet = new HashSet<>()
                    if (profile.roles) {
                        roleSet.addAll(profile.roles)
                    } else if (profile.attributes.containsKey("roles")) {
                        Object rolesObj = profile.attributes.get("roles")
                        if (rolesObj instanceof List) {
                            roleSet.addAll(rolesObj as List)
                        } else if (rolesObj instanceof Set) {
                            roleSet.addAll(rolesObj as Set)
                        }
                    }
                    for (String role : roleSet) {
                        EntityValue roleMap = ec.entity.find("moqui.security.sso.AuthFlowRoleMap")
                                .condition("authFlowId", profile.clientName)
                                .condition("roleName", role)
                                .one()
                        if (!roleMap && "Y" == authFlow.verboseMode) {
                            ec.logger.warn("No map found for role: " + role)
                        }
                        if (roleMap?.userGroupId && !obsoleteUserGroupIdSet.remove(roleMap.userGroupId)) {
                            ec.service.sync().name("create#moqui.security.UserGroupMember")
                                    .parameter("userGroupId", roleMap.userGroupId)
                                    .parameter("userId", userId)
                                    .parameter("fromDate", nowTimestamp)
                                    .call()
                        }
                        if (roleMap?.roleTypeId && !obsoleteRoleTypeIdSet.remove(roleMap.roleTypeId)) {
                            ec.service.sync().name("mantle.party.PartyServices.ensure#PartyRole")
                                    .parameter("partyId", partyId)
                                    .parameter("roleTypeId", roleMap.roleTypeId)
                                    .call()
                        }
                    }
                    for (EntityValue userGroupMember : userGroupMemberList) {
                        String userGroupId = userGroupMember.userGroupId
                        if (obsoleteUserGroupIdSet.contains(userGroupId) && userGroupId != authFlow.defaultUserGroupId) {
                            ec.service.sync().name("update#moqui.security.UserGroupMember")
                                    .parameter("userGroupId", userGroupId)
                                    .parameter("userId", userId)
                                    .parameter("fromDate", userGroupMember.fromDate)
                                    .parameter("thruDate", nowTimestamp)
                                    .call()
                        }
                    }
                    for (String roleTypeId : obsoleteRoleTypeIdSet) {
                        ec.service.sync().name("delete#mantle.party.PartyRole")
                                .parameter("partyId", partyId)
                                .parameter("roleTypeId", roleTypeId)
                                .call()
                    }

                    // add default user group if needed
                    long userGroupCount = ec.entity.find("moqui.security.UserGroupMember")
                            .condition("userId", userId)
                            .conditionDate("fromDate", "thruDate", nowTimestamp)
                            .count()
                    if (userGroupCount == 0) {
                        ec.service.sync().name("create#moqui.security.UserGroupMember")
                                .parameter("userGroupId", authFlow.defaultUserGroupId)
                                .parameter("userId", userId)
                                .parameter("fromDate", nowTimestamp)
                                .call()
                    }

                    // add default role if needed
                    long partyRoleCount = ec.entity.find("mantle.party.PartyRole")
                            .condition("partyId", partyId)
                            .count()
                    if (partyRoleCount == 0) {
                        ec.service.sync().name("mantle.party.PartyServices.ensure#PartyRole")
                                .parameter("partyId", partyId)
                                .parameter("roleTypeId", "_NA_")
                                .call()
                    }
                }
            }
        }

        return null
    }
}
