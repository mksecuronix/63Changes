package com.securonix.snyperpolicyengine.ie;

import com.securonix.application.common.CommonUtility;
import com.securonix.application.common.JAXBUtilImpl;
import static com.securonix.application.common.search.SearchConstants.AND;
import static com.securonix.application.common.search.SearchConstants.CONDITION_CONTAINS;
import static com.securonix.application.common.search.SearchConstants.CONDITION_CONTAINS_IN_LIST;
import static com.securonix.application.common.search.SearchConstants.CONDITION_DOES_NOT_CONTAIN;
import static com.securonix.application.common.search.SearchConstants.CONDITION_DOES_NOT_CONTAIN_IN_LIST;
import static com.securonix.application.common.search.SearchConstants.CONDITION_DOES_NOT_END_WITH;
import static com.securonix.application.common.search.SearchConstants.CONDITION_DOES_NOT_START_WITH;
import static com.securonix.application.common.search.SearchConstants.CONDITION_ENDS_WITH;
import static com.securonix.application.common.search.SearchConstants.CONDITION_ENDS_WITH_IN_LIST;
import static com.securonix.application.common.search.SearchConstants.CONDITION_EQUALS;
import static com.securonix.application.common.search.SearchConstants.CONDITION_EQUALS_IN_LIST;
import static com.securonix.application.common.search.SearchConstants.CONDITION_GREATER_THAN;
import static com.securonix.application.common.search.SearchConstants.CONDITION_GREATER_THAN_OR_EQUALS;
import static com.securonix.application.common.search.SearchConstants.CONDITION_IS_NOT_NULL;
import static com.securonix.application.common.search.SearchConstants.CONDITION_IS_NULL;
import static com.securonix.application.common.search.SearchConstants.CONDITION_LESS_THAN;
import static com.securonix.application.common.search.SearchConstants.CONDITION_LESS_THAN_OR_EQUALS;
import static com.securonix.application.common.search.SearchConstants.CONDITION_NOT_EQUALS;
import static com.securonix.application.common.search.SearchConstants.CONDITION_NOT_EQUALS_IN_LIST;
import static com.securonix.application.common.search.SearchConstants.CONDITION_STARTS_WITH;
import static com.securonix.application.common.search.SearchConstants.CONDITION_STARTS_WITH_IN_LIST;
import static com.securonix.application.common.search.SearchConstants.OR;
import static com.securonix.application.common.search.SearchConstants.REGEX_EQUALS;
import static com.securonix.application.common.search.SearchConstants.REGEX_NOT_EQUALS;
import com.securonix.application.common.stopwatch.Stopwatch;
import com.securonix.application.exception.common.ConfigReaderException;
import com.securonix.application.hadoop.uiUtil.websocket.MappedAttributeList;
import com.securonix.application.hibernate.tables.Configlookupimport;
import com.securonix.application.hibernate.tables.Configtpiimport;
import com.securonix.application.hibernate.tables.PolicyMaster;
import com.securonix.application.hibernate.tables.Resourceattributes;
import com.securonix.application.hibernate.util.DbUtil;
import com.securonix.application.license.EncryptionUtil;
import com.securonix.application.lookup.LookUpCoreBean;
import com.securonix.application.policy.PolicyConstants;
import static com.securonix.application.policy.PolicyConstants.AT_CUSTOM;
import static com.securonix.application.policy.PolicyConstants.AT_LAND_SPEED;
import static com.securonix.application.policy.PolicyConstants.AT_PHISHING;
import static com.securonix.application.policy.PolicyConstants.AT_TIER2_SUMMARY;
import static com.securonix.application.policy.PolicyConstants.TYPE_REALTIME;
import com.securonix.application.policy.beans.functions.DirectiveParametersBean;
import com.securonix.application.policy.beans.functions.FunctionBean;
import com.securonix.application.policy.beans.functions.FunctionConfigReader;
import com.securonix.application.policy.beans.functions.FunctionParametersBean;
import com.securonix.application.policy.beans.functions.FunctionType;
import com.securonix.application.profiler.attributes.AttributeMeta;
import com.securonix.application.profiler.attributes.AttributeMetaListInfo;
import com.securonix.application.profiler.uiUtil.ResourceUtilImpl;
import com.securonix.hadoop.util.OpsLogger;
import com.securonix.hadoop.util.SnyperUtil;
import com.securonix.hbaseutil.HBaseClient;
import com.securonix.of.Operator;

import com.securonix.of.OperatorException;
import com.securonix.snyper.common.EnrichedEventObject;
import com.securonix.snyper.config.beans.ConditionBean;
import com.securonix.snyper.config.beans.GroupBean;
import com.securonix.snyper.config.beans.HadoopConfigBean;
import com.securonix.snyper.config.beans.KafkaConfigBean;
import com.securonix.snyper.config.beans.PolicyConfigBean;
import com.securonix.snyper.policyengine.PolicyUtil;
import com.securonix.application.policy.beans.functions.DirectiveConditionBean;
import com.securonix.application.policy.beans.functions.LandSpeedParameterBean;
import com.securonix.application.proxyanalyzer.PhishingConfig;
import com.securonix.application.proxyanalyzer.ProxyAnalyzerCheck;
import com.securonix.application.proxyanalyzer.ProxyAnalyzerConfigBean;
import com.securonix.application.proxyanalyzer.ProxyAnalyzerConstants.PHISHING_ATTRIBUTE;
import static com.securonix.application.snyper.uiUtil.policy.PolicyUIUtil.POSTPROCESSFUNCTIONS.CHECK_AGAINST_TPI_CORE;
import static com.securonix.application.snyper.uiUtil.policy.PolicyUIUtil.POSTPROCESSFUNCTIONS.CHECK_AGAINST_ACTIVELIST;
import com.securonix.application.suspect.ViolationInfoBuildUtil;
import com.securonix.data.distributor.Tier2ConfigLoader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import scala.Tuple2;
import java.util.regex.*;
import static java.util.regex.Pattern.CASE_INSENSITIVE;
import com.securonix.kafkaclient.beans.Counter;
import com.securonix.snyper.policy.beans.ViolationDisplayConfigBean;
import com.securonix.hadoop.util.OpsLogger.SOURCE;
import com.securonix.hadoop.util.OpsLogger.SEVERITY;
import com.securonix.of.Operator.DATA_TYPE;
import com.securonix.of.Parameter;
import com.securonix.of.ParameterInfo;
import com.securonix.redis.RedisClient;
import static com.securonix.redis.RedisConstants.HEADERDELIMITER;
import static com.securonix.redis.RedisConstants.SOURCELOOKUP;
import com.securonix.redis.RedisNamespaceConstants;
import com.securonix.snyper.common.MiniEEO;
import com.securonix.snyper.common.util.EEOUtil;
import com.securonix.snyper.common.util.ViolatorUtil;
import com.securonix.snyper.config.beans.HBaseConfigBean;
import com.securonix.snyper.config.beans.RedisConfigBean;
import com.securonix.snyper.config.beans.ZookeeperConfigBean;
import com.securonix.snyper.policy.beans.IEFunctionResponse;
import com.securonix.snyper.policy.beans.violations.Violation;

import com.securonix.snyper.util.DateUtil;
import com.securonix.snyper.violationinfo.beans.VerboseInfoDetails;
import com.securonix.snyper.violationinfo.beans.ViolationDetails;
import com.securonix.snyper.violationinfo.beans.ViolationDetailsFactory;
import com.securonix.snyper.violationinfo.beans.ViolationDetailsTree;
import com.securonix.snyper.violationinfo.beans.ViolationInfo;
import com.securonix.snyper.violationinfo.beans.ViolationInfoConstants;
import static com.securonix.snyperpolicyengine.ie.IEFunctionProcessor.SERIALIZER;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Processor that applies policies to individual events
 *
 * @author Securonix Inc.
 */
public class IEProcessor {

    /**
     * Logger for the class
     */
    private final static Logger LOGGER = LogManager.getLogger();
    /**
     * Map to hold counts of processed events and violations found
     */
    private final Map<String, Map<String, Counter>> IEE_COUNTS = new HashMap<>();
    /**
     * Flag to indicate if the counts are to be published to the Kafka topic
     */
    private final boolean updateCounts;
    /**
     * Map holding policies against resource groups
     */
    private final static Map<Long, Map<Long, PolicyMaster>> POLICY_MAP = new ConcurrentHashMap<>();
    private final static Map<Long, List<GroupBean>> GROUP_MAP = new ConcurrentHashMap<>();
    private final static Map<Long, Boolean> DIRECTIVES_MAP = new ConcurrentHashMap<>();
    private final static Map<String, FunctionParametersBean> DIRECTIVES = new ConcurrentHashMap<>();
    /**
     * Holds references to function processors per policy
     */
    private final static Map<Long, IEFunctionProcessor> FUNCTION_PROCESSORS = new ConcurrentHashMap<>();
    /**
     * Set of resource groups without any IEE policies
     */
    private final static Set<Long> NO_POLICIES = new CopyOnWriteArraySet();

    Map<Long, Set<Long>> typeRgMap = new HashMap<>();

    Map<String, Set<Long>> functionRgMap = new HashMap<>();

    /**
     * Utility class for logging errors
     */
    private final SnyperUtil snyperUtil = new SnyperUtil();

    /**
     * Set of updated policies
     */
    private final Map<Long, Set<Long>> rgToChangedPolicies = new ConcurrentHashMap();
    /**
     * Set to hold paused policies
     */
    private final Set<Long> pausedPolicies = new CopyOnWriteArraySet();
    private final Set<Long> changedWhitelists = new CopyOnWriteArraySet();

    private HashMap<Long, Tuple2<ViolationDisplayConfigBean, List<String>>> vInfoConfig = new HashMap<>();

//    private Map<Long, HashSet<String>> encryptedMappedAttributesMap = new HashMap<>();
    private Map<Long, Map<String, String>> MULTIVALUED_ATTRIBUTES = new HashMap<>();
    private HashSet RG_ATTRIBUTES_processed = new HashSet<>();
    private Boolean tpiUpdated = false;
    private Boolean activelistUpdated = false;
    private Boolean lookupUpdated = false;
    private Boolean globalwhitelistUpdated = false;

    /**
     * Key for encryption / decryption
     */
    private static final String PASSKEY = EncryptionUtil.INSTANCE.getEncryptionKey();
    /**
     * Hadoop configuration
     */
    private final HadoopConfigBean hcb;

    private final static Map<String, Pattern> PATTERNS = new MaxSizeHashMap<>(1900);
    /**
     * Redis client
     */
    private final RedisClient redisClient = RedisClient.INSTANCE;

    private ReentrantLock lock = new ReentrantLock();

    private WhiteListProcessor whiteListProcessor;
    private final Map<Long, String> LAND_SPEED_IP_ATTRIBUTE = new ConcurrentHashMap<>();
    private WhiteListedIps whiteListedIps = null;
    private WhiteList alexa = null;

    private Map<Long, List<Resourceattributes>> resourceAttributeMap = new HashMap<>();

    static class MaxSizeHashMap<K, V> extends java.util.LinkedHashMap<K, V> {

        private final int maxSize;

        public MaxSizeHashMap(int maxSize) {
            super(16, 0.75f, true);
            this.maxSize = maxSize;
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
            return size() > maxSize;
        }
    }

    private String compressionType;

    public String getCompressionType() {
        return compressionType;
    }

    public IEProcessor(final HBaseClient hbaseClient, final HadoopConfigBean hcb, final int countsUpdateFrequency) {

        this.hcb = hcb;
        this.compressionType = hcb.getKafkaConfigBean().getCompressionType();

        redisClient.initialize(hcb.getRedisConfigBean());

        this.whiteListProcessor = new WhiteListProcessor(hcb);

        updateCounts = false;

        getLookupByTenants();
        getTpiByTenants();

    }

    public static final Map<String, Long> lookupNameWithTenantId = new ConcurrentHashMap<>();
    public static final Map<String, Long> tpiNameWithTenantId = new ConcurrentHashMap<>();
    private static final Map<String, Long> activeListsNameWithTenantId = new ConcurrentHashMap<>();

    private void getLookupByTenants() {
        String query = "From Configlookupimport";
        List<Configlookupimport> executeHQLQuery = DbUtil.executeHQLQuery(query);
        executeHQLQuery.forEach((configlookupimport) -> {
            lookupNameWithTenantId.put(configlookupimport.getTablename().toUpperCase(), configlookupimport.getTenantid() != null ? configlookupimport.getTenantid() : 0l);
        });
    }

    private void getTpiByTenants() {
        String query = "From Configtpiimport";
        List<Configtpiimport> executeHQLQuery = DbUtil.executeHQLQuery(query);
        executeHQLQuery.forEach((configtpiimport) -> {
            tpiNameWithTenantId.put(configtpiimport.getTpiname().toUpperCase(), configtpiimport.getTenantid() != null ? configtpiimport.getTenantid() : 0l);
        });
    }

//    private void getActiveListsByTenants() {
//       String query = "From Configactivelist";
//       List<Configactivelist> executeHQLQuery = DbUtil.executeHQLQuery(query);
//       executeHQLQuery.forEach((configactivelist) -> {
//           List<Configactivelist> executeHQLQuery = DbUtil.executeHQLQuery(query);
//           activeListsNameWithTenantId.put(configactivelist.getActiveListName(), configactivelist.getTenantid() != null ? configlookupimport.getTenantid() : -1l);
//       });
//    }
    /**
     * Sets updated policies, called from driver when control flags are received
     *
     * @param changedPolicies Updated policies
     */
    public void setChangedPolicies(final Set<Long> changedPolicies) {

        try {
            for (Long changedPolicy : changedPolicies) {
                PolicyMaster pm = PolicyUtil.getPolicy(changedPolicy);
                if (pm != null) {
                    if (pm.getResourceGroupId() != -1) {
                        Set<Long> oldChangedPolicies = this.rgToChangedPolicies.get(pm.getResourceGroupId());
                        if (oldChangedPolicies == null) {
                            oldChangedPolicies = new HashSet<>();
                            this.rgToChangedPolicies.put(pm.getResourceGroupId(), oldChangedPolicies);
                        }
                        oldChangedPolicies.add(changedPolicy);
                    } else if (pm.getResourceGroupId() == -1 && pm.getResourcetypeid() == -1) {
                        Set<Long> rgIdMap = functionRgMap.get(pm.getFunctionality());
                        if (rgIdMap != null) {
                            for (Long rgId : rgIdMap) {
                                Set<Long> oldChangedPolicies = this.rgToChangedPolicies.get(rgId);
                                if (oldChangedPolicies == null) {
                                    oldChangedPolicies = new HashSet<>();
                                    this.rgToChangedPolicies.put(rgId, oldChangedPolicies);
                                } else {
                                    LOGGER.warn("[PId:{} Functionality:{}] oldChangedPolicies size {}: ", pm.getId(), pm.getFunctionality(), oldChangedPolicies.size());
                                }
                                oldChangedPolicies.add(changedPolicy);
                            }
                        } else {
                            LOGGER.debug("[PId:{} Functionality:{}] No resourcegroups found for functionality yet", pm.getId(), pm.getFunctionality());
                        }
                    }
                } else {
                    LOGGER.warn("[PId:{}] Not found while setting changed policies", changedPolicy);
                }
            }

            this.pausedPolicies.removeAll(changedPolicies);
            // clear no policies set
            NO_POLICIES.clear();

            LOGGER.trace("Policies CHANGED- {}", changedPolicies);
        } catch (Exception ex) {
            LOGGER.warn("Error setting changed policies", ex);
        }
    }

    public void setDeletedPolicies(final Set<Long> deletedPolicies) {
        if (deletedPolicies != null) {
            synchronized (POLICY_MAP) {
                // Delete it here for all rg_ids because we don't know the functionality of the policy
                for (Long policyId : deletedPolicies) {
                    Set<Entry<Long, Map<Long, PolicyMaster>>> entrySet = POLICY_MAP.entrySet();
                    for (Entry<Long, Map<Long, PolicyMaster>> entry : entrySet) {
                        entry.getValue().remove(policyId);
                    }
                    GROUP_MAP.remove(policyId);
                    DIRECTIVES_MAP.remove(policyId);
                    FUNCTION_PROCESSORS.remove(policyId);
                }
            }
        }
        LOGGER.trace("Policies DELETED- {}", deletedPolicies);
    }

    public void setPausedPolicies(final Set<Long> pausedPolicies) {
        this.pausedPolicies.addAll(pausedPolicies);
        LOGGER.trace("Policies PAUSED- {}", pausedPolicies);
    }

    public void setChangedWhitelistConfigs(final Set<Long> changedWhitelists) {
        this.changedWhitelists.addAll(changedWhitelists);
        LOGGER.trace("Whitelists CHANGED- {}", changedWhitelists);
    }

    private final static String HQL_GET_REALTIME_POLICIES_FOR_FUNCTIONAILTY
            = "From PolicyMaster where enabled = 1 and functionality = :functionality and type = :type and (resourceGroupId = -1 or resourceGroupId=:resourceGroupId)";

    private List<PolicyMaster> getRealtimePoliciesByFunctionality(String functionality, final long resourceGroupId) {
        try {
            LOGGER.info("Loading realtime policies for functionality- {} [Q:{}] [resourceGroupId:{}]", functionality, HQL_GET_REALTIME_POLICIES_FOR_FUNCTIONAILTY, resourceGroupId);
            //If Funtionality is null from the eeo (ideally shouldnt be) Getting functionality from RG table (SNYP-25094)
            if(functionality == null || functionality.trim().isEmpty()) {
                LOGGER.info("functionality is null skipping - {} for rgid {} <<< need to check", functionality, resourceGroupId);
                return null;
            }
            Map<String, Object> params = new HashMap<>();
            params.put("functionality", functionality);
            params.put("type", TYPE_REALTIME);
            params.put("resourceGroupId", resourceGroupId);

            final List<PolicyMaster> policies = DbUtil.executeHQLQuery(HQL_GET_REALTIME_POLICIES_FOR_FUNCTIONAILTY, params, false);
            return policies;
        } catch (Exception ex) {
            LOGGER.error("Error Getting Realtime policies For functionality {}, ResourcegroupId {} Error Trace {}", functionality, resourceGroupId, ex);
            return null;
        }
    }

    /**
     * Loads IEE & AEE policies for the given resource group
     *
     * @param resourceGroupId Resource group
     *
     * @return List of policies, read from MySql (policy_master table), for the
     * given resource group
     */
    private Map<Long, PolicyMaster> loadPolicies(final long resourceGroupId, final long tenantId, final long resourceTypeId, final String functionality) {

        LOGGER.debug("[RgId:{}] [RtId:{}] Loading realtime policies ..", resourceGroupId, resourceTypeId);
        OpsLogger.log(SOURCE.IEE, String.format("[RgId:%s] Loading policies ..", resourceGroupId));

        final List<PolicyMaster> policies = getRealtimePoliciesByFunctionality(functionality, resourceGroupId);

        if (!typeRgMap.containsKey(resourceTypeId)) {
            typeRgMap.put(resourceTypeId, new HashSet<Long>() {
                {
                    add(resourceGroupId);
                }
            });
        } else {
            typeRgMap.get(resourceTypeId).add(resourceGroupId);
        }

        if (!functionRgMap.containsKey(functionality)) {
            functionRgMap.put(functionality, new HashSet<Long>() {
                {
                    add(resourceGroupId);
                }
            });
        } else {
            functionRgMap.get(functionality).add(resourceGroupId);
        }

        Set<Long> resourceGroupIds = typeRgMap.get(resourceTypeId);
        Set<Long> functionalityRgs = functionRgMap.get(functionality);
        if (policies != null && !policies.isEmpty()) {

            LOGGER.debug("[RgId:{}] Policies loaded # {}", resourceGroupId, policies.size());

            String xml;

            LOGGER.debug("[RgId:{}] Loading GETTERS for policies ..", resourceGroupId);
            for (PolicyMaster policy : policies) {
                try {
                    LOGGER.trace("Loading for policy:{}", policy.getName());

                    long policyId = policy.getId();
                    xml = policy.getDirectiveConfig();

                    if (xml != null) {
                        if (policy.getResourceGroupId() != -1) {

                            if (POLICY_MAP.containsKey(policy.getResourceGroupId())) {
                                POLICY_MAP.get(policy.getResourceGroupId()).put(policyId, policy);
                            } else {
                                POLICY_MAP.put(policy.getResourceGroupId(), new ConcurrentHashMap<Long, PolicyMaster>() {
                                    {
                                        put(policyId, policy);
                                    }
                                });

                            }

                        } else if (policy.getResourcetypeid() != -1) {

                            //                        for (Long rgId : resourceGroupIds) {
                            if (POLICY_MAP.containsKey(resourceGroupId)) {
                                POLICY_MAP.get(resourceGroupId).put(policyId, policy);
                            } else {
                                POLICY_MAP.put(resourceGroupId, new ConcurrentHashMap<Long, PolicyMaster>() {
                                    {
                                        put(policyId, policy);
                                    }
                                });
                            }
                            //                        }

                        } else if (policy.getResourcetypeid() == -1 && policy.getResourceGroupId() == -1) {
                            //&& functionalityRgs != null) {
                            LOGGER.trace("Satisfied functionailty");

                            //                        for (Long rgId : functionalityRgs) {
                            if (POLICY_MAP.containsKey(resourceGroupId)) {
                                POLICY_MAP.get(resourceGroupId).put(policyId, policy);
                            } else {
                                POLICY_MAP.put(resourceGroupId, new ConcurrentHashMap<Long, PolicyMaster>() {
                                    {
                                        put(policyId, policy);
                                    }
                                });
                                //                            }
                            }
                        }
                        processPolicyConfig(xml, policyId, policy, resourceGroupId);

                        if (resourceGroupId != policy.getResourceGroupId() && policy.getResourceGroupId() != -1) {

                            LOGGER.trace("[PId:{}] RGID MISMATCH FOUND -- P-RgId:{} RgId:{}", policyId, policy.getResourceGroupId(), resourceGroupId);
                            if (POLICY_MAP.containsKey(resourceGroupId)) {
                                POLICY_MAP.get(resourceGroupId).put(policyId, policy);
                            } else {
                                POLICY_MAP.put(resourceGroupId, new ConcurrentHashMap<Long, PolicyMaster>() {
                                    {
                                        put(policyId, policy);
                                    }
                                });
                            }
                        }
                    } else {
                        OpsLogger.log(SOURCE.IEE, SEVERITY.MEDIUM, String.format("Configuration XML not available for policy Id- %s", policyId));
                        snyperUtil.logError(tenantId, -1L, policyId, "Configuration XML not available for policy");
                    }
                } catch (Exception ex) {
                    LOGGER.error("Error loading policy config for PID:{}", policy.getId());
                    OpsLogger.log(SOURCE.IEE, SEVERITY.MEDIUM, String.format("Error loading policy config for Policy Id- %s", policy.getId()));
                }
            }
        } else {
            // maintain a list of resource groups for which policies are not available!
            OpsLogger.log(SOURCE.IEE, String.format("No policies available YET for resource group Id- %s", resourceGroupId), new HashMap<>());
            NO_POLICIES.add(resourceGroupId);
        }

        return POLICY_MAP.get(resourceGroupId);
    }

    /**
     * Process policy configuration, collects GETTERS before hand for retrieving
     * values from events
     *
     * @param xml Configuration XML for the policy
     * @param policyId Policy Id
     * @param policy Policy object
     * @param resourceGroupId Resource group id of the event
     */
    private void processPolicyConfig(final String xml, final long policyId, final PolicyMaster policy, final long resourceGroupId) {

        LOGGER.debug("[PId:{}] Parsing XML- {}", policyId, xml);
        final PolicyConfigBean bean = (PolicyConfigBean) JAXBUtilImpl.xmlToPojo(xml, PolicyConfigBean.class);
        final List<GroupBean> groups = bean.getGroups();

        OpsLogger.log(SOURCE.IEE, String.format("[PId-%s] Updating groups # %s", policyId, (groups == null ? "N/A" : groups.size())));

        LOGGER.debug("[PId:{}] Groups? {}", policyId, (groups == null ? "N/A" : groups.size()));
        if (groups != null && !groups.isEmpty()) {
            GROUP_MAP.put(policyId, groups);
        } else {
            OpsLogger.log(SOURCE.IEE, String.format("[PId-%s] Groups (filtering criteria) not available, so all events are violations!", policyId));
        }

        // this is required to avoid NPE later - AEE is IEE with directives!    
        DIRECTIVES_MAP.put(policyId, policy.isDirectiveEnabled() && policy.isFunctionEnabled());

        LOGGER.debug("[PId:{}] Function enabled? {}:{}:{}", policyId, policy.isFunctionEnabled(), policy.getAnalyticstype(), policy.getFunctionConfig());

        if (AT_PHISHING.equals(policy.getAnalyticstype())) {
            LOGGER.debug("[PId:{}] EMAIL PHISHING POLICY AVAILABLE- {}:{}", policy.getId(), policy.getName(), policy.getAnalyzerConfig());
            final ProxyAnalyzerConfigBean pacb = (ProxyAnalyzerConfigBean) JAXBUtilImpl.xmlToPojo(policy.getAnalyzerConfig(), ProxyAnalyzerConfigBean.class);
            loadPhishingGetters(policyId, pacb);
            DIRECTIVES_MAP.put(policyId, true);
        }

        if (policy.isFunctionEnabled()) {

            // even phishing policies may have functions
            final FunctionConfigReader fcr = new FunctionConfigReader();
            try {
                if (policy.getFunctionConfig() != null) {

                    final Map<String, FunctionParametersBean> functionConfigs = fcr.readConfigs(policy.getFunctionConfig());
                    final boolean multifunction = fcr.isMultiFunction();
                    final FunctionBean fb = new FunctionBean(multifunction, functionConfigs);

                    LOGGER.debug("[PId:{}] Function configs- {}", policyId, functionConfigs);
                    if (functionConfigs != null) {

                        // to identify multi-value attributes
                        final Map<String, String> dMap = new HashMap<>();
                        final List<Resourceattributes> attributes = ResourceUtilImpl.getResourceGroupAttributesFromDB(resourceGroupId);

                        attributes.stream().forEach(attribute -> {
                            final String metaData = attribute.getMetalist();
                            //LOGGER.trace("[PId:{}] Attribute:{} MetaList:{}", policyId, attribute.getAttribute(), metaData);
                            if (metaData != null && !metaData.isEmpty()) {
                                final List<AttributeMeta> metalist = (JAXBUtilImpl.xmlToPojos(metaData, AttributeMeta.class));
                                if (metalist != null && !metalist.isEmpty()) {
                                    final AttributeMeta am = metalist.get(0);
                                    final Map<String, String> map = am.getMetaList();
                                    if (map != null) {
                                        if (Boolean.parseBoolean(map.get(AttributeMetaListInfo.MULTI_VALUED))) {
                                            final String mvDelimiter = map.get(AttributeMetaListInfo.MV_DELIMITER);
                                            if (mvDelimiter != null && !mvDelimiter.isEmpty()) {
                                                dMap.put(attribute.getMappedattribute(), mvDelimiter);
                                                LOGGER.debug("[PId:{}] MV-Attribute:{} MappedAttribute:{} Delimiter:{}",
                                                        policyId, attribute.getAttribute(),
                                                        attribute.getMappedattribute(), mvDelimiter);
                                            }
                                        }
                                    }
                                } else {
                                    OpsLogger.log(SOURCE.IEE, SEVERITY.MEDIUM, String.format("[PId-%s] Unable to parse meta list for %s", policyId, attribute.getAttribute()));
                                }
                            }
                        });

                        FUNCTION_PROCESSORS.put(policyId, new IEFunctionProcessor(fb, snyperUtil, policyId, dMap, hcb.getSolrConfigBean(), policy));

                        // retrieve directive functions for the policy
                        DirectiveParametersBean dpb = null;
                        LandSpeedParameterBean lsb = null;

                        for (Entry<String, FunctionParametersBean> entry : functionConfigs.entrySet()) {
                            if (entry.getValue().getType() == FunctionType.DIRECTIVE) {
                                // assuming that this is a parent directive
                                dpb = (DirectiveParametersBean) entry.getValue();
                                DIRECTIVES.put(policyId + "_" + dpb.getName(), dpb);
                                LOGGER.debug("[PId:{}] Adding to Directive map- {}", policyId, (policyId + "_" + dpb.getName()));

                                collectDirectives(policyId, dpb.getChildBean());
                                break;
                            } else if (entry.getValue().getType() == FunctionType.LAND_SPEED_CHECK) {
                                lsb = (LandSpeedParameterBean) entry.getValue();
                                LAND_SPEED_IP_ATTRIBUTE.put(policyId, lsb.getIpAttribute() == null ? MappedAttributeList.IPADDRESS : lsb.getIpAttribute());
                                DIRECTIVES.put(policyId + "_" + lsb.getName(), lsb);
                                LOGGER.debug("[PId:{}] Adding to Directive map- {} LS-IPAttr:{}", policyId, (policyId + "_" + lsb.getName()), lsb.getIpAttribute());
                                break;
                            }
                        }

                        LOGGER.debug("[PId:{}] Directives available? {}", policyId, (dpb != null || lsb != null));

                        // if directive available ..
                        if (dpb != null) {
                            LOGGER.debug("[PId:{}] Loading GETTERS for {} ..", policyId, dpb.getName());
                            loadDirectiveGetters(policyId, dpb);
                        } else if (lsb != null) {
                            LOGGER.debug("[PId:{}] Loading GETTERS for {} ..", policyId, lsb.getName());
                            loadLandSpeedGetters(policyId, lsb);
                        } else {
                            // directives are not available!
                            DIRECTIVES_MAP.put(policyId, AT_PHISHING.equals(policy.getAnalyticstype()));
                        }

                    } else {
                        LOGGER.warn("[PId:{}] Unable to parse function config- {}", policyId, policy.getFunctionConfig());
                    }
                } else {
                    LOGGER.warn("[PId:{}] Function configuration not available!", policyId);
                }
            } catch (ConfigReaderException ex) {
                LOGGER.error("[PId:{}] Error reading function configuration", policyId, ex);
                OpsLogger.log(SOURCE.IEE, SEVERITY.HIGH, String.format("[PId-%s] Error reading function configuration", policyId, ex));
            }
        }

    }

    private void collectDirectives(final long policyId, DirectiveParametersBean dpb) {

        if (dpb != null) {
            DIRECTIVES.put(policyId + "_" + dpb.getName(), dpb);
            LOGGER.debug("[PId:{}] Adding to Directive map- {}", policyId, (policyId + "_" + dpb.getName()));

            collectDirectives(policyId, dpb.getChildBean());
        }
    }

    private final static Map<Long, Map<String, Map<String, Method>>> GETTERS_PER_POLICY = new ConcurrentHashMap();
    private final static Class EEO_CLASS = EnrichedEventObject.class;
    private static final Pattern PATTERN_CROSS_DIRECTIVE_ATTRIBUTE = Pattern.compile("^(\\d+[.]\\w+)", Pattern.CASE_INSENSITIVE);

    private void loadPhishingGetters(final long policyId, final ProxyAnalyzerConfigBean pacb) {

        Map<String, Map<String, Method>> gettersPerConfig = GETTERS_PER_POLICY.get(policyId);
        if (gettersPerConfig == null) {
            GETTERS_PER_POLICY.put(policyId, gettersPerConfig = new HashMap<>());
        }

        final Map<String, Method> gettersForAttributes = gettersPerConfig.getOrDefault("GA", new LinkedHashMap<>());

        final List<ProxyAnalyzerCheck> checks = pacb.getChecks();
        LOGGER.debug("[PId:{}] Checks available # {}", policyId, (checks == null ? "N/A" : checks.size()));

        if (checks != null && !checks.isEmpty()) {
            checks.forEach(check -> {
                final PhishingConfig pc = (PhishingConfig) check;
                String attribute = pc.getAttributes().get(PHISHING_ATTRIBUTE.SENDER);
                LOGGER.debug("[PId:{}] SENDER- {}", policyId, attribute);
                if (!gettersForAttributes.containsKey(attribute)) {
                    try {
                        gettersForAttributes.put(attribute, EEO_CLASS.getMethod("get" + attribute.substring(0, 1).toUpperCase() + attribute.substring(1), (Class[]) null));
                    } catch (NoSuchMethodException | SecurityException ex) {
                        LOGGER.error("[PId:{}] Getter not found for {}", policyId, attribute, ex);
                    }
                }
            });
        }

        LOGGER.debug("[PId:{}] GA # {}", policyId, gettersForAttributes.size());
        gettersPerConfig.put("GA", gettersForAttributes);
        gettersPerConfig.put("CA", new LinkedHashMap<>());
    }

    private void loadLandSpeedGetters(final long policyId, final LandSpeedParameterBean lsb) {

        Map<String, Map<String, Method>> gettersPerDirective = GETTERS_PER_POLICY.get(policyId);
        if (gettersPerDirective == null) {
            GETTERS_PER_POLICY.put(policyId, gettersPerDirective = new HashMap<>());
        }

        String[] attributesArray = lsb.getGroups();

        final String directiveName = lsb.getName();
        Map<String, Method> gettersForAttributes = gettersPerDirective.getOrDefault("GA", new LinkedHashMap<>());

        LOGGER.debug("[PId:{}] LS:{} Attributes # {}", policyId, directiveName, attributesArray.length);

        String getterMethod;
        Method method;

        for (String attribute : attributesArray) {

            if (!gettersForAttributes.containsKey(attribute)) {
                getterMethod = "get" + attribute.substring(0, 1).toUpperCase() + attribute.substring(1);
                try {
                    method = EEO_CLASS.getMethod(getterMethod, (Class[]) null);
                    gettersForAttributes.put(attribute, method);
                } catch (NoSuchMethodException | SecurityException ex) {
                    LOGGER.error("[PId:{}] Getter not found for {}", policyId, attribute, ex);
                    OpsLogger.log(SOURCE.IEE, SEVERITY.HIGH, String.format("[PId-%s] Getter not found for %s", policyId, attribute));
                }
            }
        }

        LOGGER.debug("[PId:{}] Directive:{} GA # {}", policyId, directiveName, gettersForAttributes.size());
        gettersPerDirective.put("GA", gettersForAttributes);
        gettersPerDirective.put("CA", new LinkedHashMap<>()); // to avoid NPE
        LOGGER.debug("[PId:{}] Getters added for {}", policyId, directiveName);
    }

    private void loadDirectiveGetters(final long policyId, DirectiveParametersBean dpb) {

        // map to hold GETTERS per DIRECTIVE for grouping / cross attributes, if any
        Map<String, Map<String, Method>> gettersPerDirective = GETTERS_PER_POLICY.get(policyId);
        if (gettersPerDirective == null) {
            GETTERS_PER_POLICY.put(policyId, gettersPerDirective = new HashMap<>());
        }

        // retrieve GETTERS
        String[] attributesArray;
        if (dpb.getParentBean() == null) { // this is a parent directive
            attributesArray = dpb.getGroups();
        } else {
            attributesArray = dpb.getCrossAttributesArray();
        }

        final String directiveName = dpb.getName();
        Map<String, Method> gettersForAttributes = gettersPerDirective.getOrDefault(dpb.getParentBean() == null ? "GA" : "CA", new LinkedHashMap<>());

        LOGGER.debug("[PId:{}] Directive:{} Attributes # {}", policyId, directiveName, attributesArray.length);

        String getterMethod;
        Method method;

        for (String attribute : attributesArray) {

            if (!gettersForAttributes.containsKey(attribute)) {
                getterMethod = "get" + attribute.substring(0, 1).toUpperCase() + attribute.substring(1);
                try {
                    method = EEO_CLASS.getMethod(getterMethod, (Class[]) null);
                    gettersForAttributes.put(attribute, method);
                } catch (NoSuchMethodException | SecurityException ex) {
                    LOGGER.error("[PId:{}] Getter not found for {}", policyId, attribute, ex);
                    OpsLogger.log(SOURCE.IEE, SEVERITY.HIGH, String.format("[PId-%s] Getter not found for %s", policyId, attribute));
                }
            }
        }

        LOGGER.debug("[PId:{}] Directive:{} GA # {}", policyId, directiveName, gettersForAttributes.size());
        gettersPerDirective.put(dpb.getParentBean() == null ? "GA" : "CA", gettersForAttributes);
        LOGGER.debug("[PId:{}] Getters added for {}", policyId, directiveName);

        // for conditions
        final List<DirectiveConditionBean> conditionList = dpb.getConditionList();
        if (conditionList != null) {

            gettersForAttributes = gettersPerDirective.get("CA");
            if (gettersForAttributes == null) {
                gettersPerDirective.put("CA", gettersForAttributes = new LinkedHashMap<>());
            }
            for (DirectiveConditionBean dcb : conditionList) {

                String attribute = dcb.getAttribute();
                if (!gettersForAttributes.containsKey(attribute)) {
                    getterMethod = "get" + attribute.substring(0, 1).toUpperCase() + attribute.substring(1);
                    try {
                        gettersForAttributes.put(attribute, EEO_CLASS.getMethod(getterMethod, (Class[]) null));
                    } catch (NoSuchMethodException ex) {
                        LOGGER.error("[PId:{}] Getter not found for {}", policyId, attribute, ex);
                        OpsLogger.log(SOURCE.IEE, SEVERITY.HIGH, String.format("[PId-%s] Getter not found for %s", policyId, attribute));
                    }
                }

                // cross-directive support
                attribute = dcb.getValue();
                if (PATTERN_CROSS_DIRECTIVE_ATTRIBUTE.matcher(attribute).find()) {
                    attribute = attribute.substring(attribute.indexOf('.') + 1);
                    LOGGER.error("[PId:{}] CD-Attribute- {}:{}", policyId, dcb.getValue(), attribute);
                    OpsLogger.log(SOURCE.IEE, SEVERITY.HIGH, String.format("[PId-%s] CD-Attribute- %s:%s", policyId, dcb.getValue(), attribute));

                    if (!gettersForAttributes.containsKey(attribute)) {
                        getterMethod = "get" + attribute.substring(0, 1).toUpperCase() + attribute.substring(1);
                        try {
                            gettersForAttributes.put(attribute, EEO_CLASS.getMethod(getterMethod, (Class[]) null));
                        } catch (NoSuchMethodException ex) {
                            LOGGER.error("[PId:{}] Getter not found for {}", policyId, attribute, ex);
                            OpsLogger.log(SOURCE.IEE, SEVERITY.HIGH, String.format("[PId-%s] Getter not found for %s", policyId, attribute));
                        }
                    }
                }
            }
        }

        // for distinct attributes
        final String[] da = dpb.getDistinctAttributes();
        if (da != null && da.length > 0) {
            for (String attribute : da) {
                if (!gettersForAttributes.containsKey(attribute)) {
                    getterMethod = "get" + attribute.substring(0, 1).toUpperCase() + attribute.substring(1);
                    try {
                        gettersForAttributes.put(attribute, EEO_CLASS.getMethod(getterMethod, (Class[]) null));
                    } catch (NoSuchMethodException ex) {
                        LOGGER.error("[PId:{}] Getter not found for {}", policyId, attribute, ex);
                        OpsLogger.log(SOURCE.IEE, SEVERITY.HIGH, String.format("[PId-%s] Getter not found for %s", policyId, attribute));
                    }
                }
            }
        }

        // count attributeddd
        gettersForAttributes = gettersPerDirective.get("CA");
        if (gettersForAttributes == null) {
            gettersPerDirective.put("CA", gettersForAttributes = new LinkedHashMap<>());
        }

        final String countAttribute = dpb.getCountAttribute();
        if (countAttribute != null && !countAttribute.isEmpty()) {
            if (!gettersForAttributes.containsKey(countAttribute)) {
                getterMethod = "get" + countAttribute.substring(0, 1).toUpperCase() + countAttribute.substring(1);
                try {
                    gettersForAttributes.put(countAttribute, EEO_CLASS.getMethod(getterMethod, (Class[]) null));
                } catch (NoSuchMethodException ex) {
                    LOGGER.error("[PId:{}] Getter not found for {}", policyId, countAttribute, ex);
                    OpsLogger.log(SOURCE.IEE, SEVERITY.HIGH, String.format("[PId-%s] Getter not found for %s", policyId, countAttribute));
                }
            }
        }

        // recursively iterate through the nested directives
        if (dpb.getChildBean() != null) {
            loadDirectiveGetters(policyId, dpb.getChildBean());
        }

    }

    public static Map<Long, List<Resourceattributes>> getResourceAttributeMap() {
        Map<Long, List<Resourceattributes>> resourceAttributeMap = new HashMap<>();
        String query = "From Resourceattributes r where resourceid = -1 ";
        long start = System.currentTimeMillis();
        List resultList = DbUtil.executeHQLQuery(query);
        LOGGER.info("Time taken for RESOURCE ATTRIBUTE MAP FROM DB CALL : " + (System.currentTimeMillis() - start));
        for (Object o : resultList) {
            Object row = (Object) o;
            Resourceattributes r = (Resourceattributes) row;
            List<Resourceattributes> attList = resourceAttributeMap.getOrDefault(r.getResourcegroupid(), new ArrayList<Resourceattributes>());
            attList.add(r);
            resourceAttributeMap.put(r.getResourcegroupid(), attList);
        }
        return resourceAttributeMap;
    }

    /**
     * Processes individual events
     *
     * @param eeo Enriched event object
     * @param debug2
     * @param policyCountTimeInLine
     * @return List of AEE violations found
     */
    public Map<String, List<Map<String, MiniEEO>>> process(final EnrichedEventObject eeo, Map<String, Tuple2<Long, Long>> policyCountTimeInLine,
            Map<String, HashMap<String, Long>> policyPartsTimeInLine) {

        final Long resourceGroupId = eeo.getRg_id();
        LOGGER.info("[RgId:{}] Processing .. RE:{}", resourceGroupId, eeo.getRawevent());

        final Map<String, List<Map<String, MiniEEO>>> aeeViolations = new ConcurrentHashMap<>();

        final List<Violation> violations = new ArrayList<>();
        eeo.setViolations(violations);

        final List<Long> aeePolicies = new ArrayList<>();
        eeo.setAeePolicies(aeePolicies);

        final List<Violation> tier2Violations = new ArrayList<>();
        eeo.setTier2Violations(tier2Violations);

        final List<Violation> customViolations = new ArrayList<>();
        eeo.setCustomViolations(customViolations);

        Long startTimeML = System.currentTimeMillis();
        if (resourceAttributeMap == null || resourceAttributeMap.isEmpty()) {
            LOGGER.info("Loading Resource Attributes from DB ONE TIME CALL");
            resourceAttributeMap = getResourceAttributeMap();
            LOGGER.info("Size of resourceAttributeMap:{}", resourceAttributeMap.keySet());
        }
        // avoid processing an event if no policies are available for the resource group Id
        if (!NO_POLICIES.contains(resourceGroupId)) {
            if (!MULTIVALUED_ATTRIBUTES.containsKey(resourceGroupId)) {
                List<Resourceattributes> attributes = resourceAttributeMap.containsKey(resourceGroupId) ? resourceAttributeMap.get(resourceGroupId) : new ArrayList<>();
                LOGGER.info("Attributes after  calling the DB:{}. Resource Group Id:{}", attributes, resourceGroupId);

                Map<String, String> dMap = new HashMap<>();
                attributes.stream().forEach((attribute) -> {

                    final String metaData = attribute.getMetalist();
                    if (metaData != null && !metaData.isEmpty() && !MULTIVALUED_ATTRIBUTES.containsKey(resourceGroupId)) {
                        final List<AttributeMeta> metalist = (JAXBUtilImpl.xmlToPojos(metaData, AttributeMeta.class));
                        if (metalist != null && !metalist.isEmpty()) {
                            final AttributeMeta am = metalist.get(0);
                            final Map<String, String> map = am.getMetaList();
                            if (map != null) {
                                if (Boolean.parseBoolean(map.get(AttributeMetaListInfo.MULTI_VALUED))) {
                                    final String mvDelimiter = map.get(AttributeMetaListInfo.MV_DELIMITER);
                                    if (mvDelimiter != null && !mvDelimiter.isEmpty()) {
                                        dMap.put(attribute.getMappedattribute(), mvDelimiter);
                                        LOGGER.trace("MV-Attribute:{} MappedAttribute:{} Delimiter:{}",
                                                attribute.getAttribute(),
                                                attribute.getMappedattribute(), mvDelimiter);
                                    }
                                }
                            }
                        }
                    }
                });

                if (!MULTIVALUED_ATTRIBUTES.containsKey(resourceGroupId)) {
                    MULTIVALUED_ATTRIBUTES.put(resourceGroupId, dMap);
                }
//                    RG_ATTRIBUTES_processed.add(resourceGroupId);
            }
//            }

            // load policies for the resource group, if not already loaded
            Map<Long, PolicyMaster> policies = POLICY_MAP.get(resourceGroupId);
            if (policies == null || policies.isEmpty()) {

                if (eeo.getTenantid() == null) {
                    LOGGER.trace("[RgId:{}] Tenant Id is null- {}", resourceGroupId, eeo.getRawevent());
                } else if (eeo.getRg_resourcetypeid() == null) {
                    LOGGER.trace("[RgId:{}] Resource Type Id is null- {}", resourceGroupId, eeo.getRawevent());
                } else if (eeo.getRg_id() == null) {
                    LOGGER.trace("[RgId:{}] Resource Group Id is null- {}", resourceGroupId, eeo.getRawevent());
                } else {
                    LOGGER.info("****** [RgId:{}] Loading policies", resourceGroupId);
                    policies = loadPolicies(resourceGroupId, eeo.getTenantid(), eeo.getRg_resourcetypeid(), eeo.getRg_functionality());
                }
            }

            // reload the changed policies
            if (policies != null && !policies.isEmpty()) {

                startTimeML = System.currentTimeMillis();
                if (rgToChangedPolicies != null && !rgToChangedPolicies.isEmpty()) {
                    LOGGER.info("********[RgId:{}] Changed policies encountered, reloading .. # {}", resourceGroupId, rgToChangedPolicies);

                    for (Long rgIdToDo : rgToChangedPolicies.keySet()) {
                        synchronized (rgToChangedPolicies) {

                            Set<Long> changedPolicies = rgToChangedPolicies.get(rgIdToDo);
                            if (changedPolicies != null) {

                                for (final Iterator<Long> iterator = changedPolicies.iterator(); iterator.hasNext();) {

                                    final Long pId = iterator.next();
                                    if (pId > 0) { // ideally, policy Id shouldn't be less than 1

                                        final PolicyMaster policy = PolicyUtil.getPolicy(pId);
                                        synchronized (vInfoConfig) {

                                            if (vInfoConfig != null && vInfoConfig.containsKey(pId)) {
                                                vInfoConfig.remove(pId);
                                            }
                                        }

                                        if (policy == null) {
                                            OpsLogger.log(SOURCE.IEE, SEVERITY.MEDIUM, String.format("[PId-%s] Unable to load policy!", pId));
                                            continue;
                                        }

                                        OpsLogger.log(SOURCE.IEE, String.format("[PId-%s] Loading policy .. %s", pId, policy.getName()));

                                        if (TYPE_REALTIME.equals(policy.getType())) {

                                            // policies.put(pId, policy);
                                            //  processPolicyConfig(policy.getDirectiveConfig(), pId, policy, rgIdToDo);
                                            whiteListProcessor.updateWhiteListConfigForPolicy(policy, false);

                                            long policyId = policy.getId();
                                            String xml = policy.getDirectiveConfig();

                                            if (xml != null) {
                                                if (policy.getResourceGroupId() != -1) {

                                                    if (policy.isEnabled()) {

                                                        if (POLICY_MAP.containsKey(policy.getResourceGroupId())) {
                                                            POLICY_MAP.get(policy.getResourceGroupId()).put(policyId, policy);
                                                        } else {
                                                            POLICY_MAP.put(policy.getResourceGroupId(), new ConcurrentHashMap<Long, PolicyMaster>() {
                                                                {
                                                                    put(policyId, policy);
                                                                }
                                                            });

                                                        }
                                                        processPolicyConfig(xml, policyId, policy, rgIdToDo);

                                                    } else {
                                                        POLICY_MAP.remove(policy.getResourceGroupId());
                                                        GROUP_MAP.remove(pId);
                                                        DIRECTIVES_MAP.remove(pId);
                                                        FUNCTION_PROCESSORS.remove(pId);
                                                        MULTIVALUED_ATTRIBUTES.remove(policy.getResourceGroupId());
                                                        whiteListProcessor.updateWhiteListConfigForPolicy(policy, true);
                                                    }

                                                } else if (policy.getResourcetypeid() == -1 && policy.getResourceGroupId() == -1) {
                                                    //&& functionalityRgs != null) {
                                                    LOGGER.info("Satisfied functionailty");

                                                    Set<Long> rgIds = functionRgMap.get(policy.getFunctionality());

                                                    if (rgIds != null) {

                                                        for (Long rgId : rgIds) {

                                                            if (policy.isEnabled()) {
                                                                if (POLICY_MAP.containsKey(rgId)) {
                                                                    POLICY_MAP.get(rgId).put(policyId, policy);
                                                                } else {
                                                                    POLICY_MAP.put(rgId, new ConcurrentHashMap<Long, PolicyMaster>() {
                                                                        {
                                                                            put(policyId, policy);
                                                                        }
                                                                    });
                                                                }

                                                                processPolicyConfig(xml, policyId, policy, rgId);
                                                            } else {
                                                                POLICY_MAP.remove(rgId);
                                                                GROUP_MAP.remove(pId);
                                                                DIRECTIVES_MAP.remove(pId);
                                                                FUNCTION_PROCESSORS.remove(pId);
                                                                MULTIVALUED_ATTRIBUTES.remove(rgId);
                                                                whiteListProcessor.updateWhiteListConfigForPolicy(policy, true);
                                                            }

                                                        }
                                                    } else {

                                                        LOGGER.trace("No resource groups present for fucntionality:{}", policy.getFunctionality());
                                                    }
                                                }
                                            }

                                        }
                                    }
                                }
                            }
                            rgToChangedPolicies.remove(rgIdToDo);
                        }
                    }
                    policies = POLICY_MAP.get(resourceGroupId);
                    Tier2ConfigLoader.INSTANCE.reLoadPolicies();

                }

                if (policies == null || policies.isEmpty()) {

                    LOGGER.trace("No Policies available for resourcegroupid:{}", resourceGroupId);
                    return aeeViolations;
                }

                if (!changedWhitelists.isEmpty()) {
                    LOGGER.info("******[RgId:{}] CHANGED whitelists encountered, .. # {}", changedWhitelists.size());
                    synchronized (changedWhitelists) {
                        for (final Iterator<Long> iterator = changedWhitelists.iterator(); iterator.hasNext();) {
                            final Long whitelistId = iterator.next();
                            whiteListProcessor.updateWhiteLists(whitelistId);
                        }
                        changedWhitelists.clear();
                    }
                }

                // continue normal processing
                Stopwatch sw = new Stopwatch();
                Stopwatch sw2 = new Stopwatch();

                Stopwatch swTotal = new Stopwatch();
                swTotal.start();

                for (Entry<Long, PolicyMaster> entry : policies.entrySet()) {
                    HashMap<String, Long> policyPartsTimebyEEO = new HashMap<String, Long>();
                    sw.reset();
                    sw.start();

                    sw2.reset();
                    sw2.start();
                    PolicyMaster policy = entry.getValue();

                    Long policyId = policy.getId();

                    if (eeo != null && !ViolatorUtil.verifyViolationReturnType(eeo, policy.getViolator())) {
                        LOGGER.trace("[PId:{}] Policy Violator is either null or empty!", policyId);
                        continue;
                    }

                    if (pausedPolicies.contains(policyId)) {
                        LOGGER.trace("[PId:{}] Policy is paused!", policyId);
                        continue;
                    }

                    Long jobId = eeo.getJobid();

                    LOGGER.trace("[PId:{}] Applying policy .. {}:{} EEO- {}", policy.getId(), policy.getName(), GROUP_MAP.get(policy.getId()), eeo);

                    // apply filtering criteria, if available for the policy, else it's a violation
                    boolean violation;
                    boolean isAeeViolation;

                    if (GROUP_MAP.get(policy.getId()) != null) {
                        final FilterResult groupResults = new FilterResult();
                        processGroups(eeo, GROUP_MAP.get(policy.getId()), groupResults, policy.getId(), policyCountTimeInLine);
                        if (!groupResults.frList.isEmpty()) {
                            LOGGER.trace("[PId:{}] Getting results from the FilterResults list", policy.getId());
                            violation = findResult(policyId, groupResults.frList);
                            LOGGER.trace("[PId:{}] Results from the FilterResults list is violation ? {}", policy.getId(), violation);
                        } else {
                            violation = true;
                        }

                    } else {
                        violation = true;
                    }
                    policyPartsTimebyEEO.put("processGroups", sw2.getElapsedTimeInMilliSec());
                    sw2.reset();
                    sw2.start();

                    if (violation) {

                        IEFunctionProcessor functionProcessor = FUNCTION_PROCESSORS.get(policy.getId());

                        IEFunctionResponse iefr = null;
                        boolean isTier2Violation = policy.getAnalyticstype() != null ? policy.getAnalyticstype().contains(AT_TIER2_SUMMARY) || policy.getAnalyticstype().contains(PolicyConstants.AT_BEACONING) || policy.getAnalyticstype().contains(PolicyConstants.TYPE_PROXYANALYZER) || policy.getAnalyticstype().contains("RARITY") : false; //It is possible for analytics column to have multiple entries
                        boolean isCustomViolation = policy.getAnalyticstype() != null ? policy.getAnalyticstype().contains(AT_CUSTOM) : false;

                        if (functionProcessor != null) { // functions available?
                            LOGGER.trace("[PId:{}] Applying functions- RE:{}", entry.getKey(), eeo.getRawevent());
                            if (tpiUpdated && policy.getAnalyticstype().contains(CHECK_AGAINST_TPI_CORE.name())) {
                                LOGGER.trace("Tpi Updated updating cache");
                                functionProcessor.reloadTpiDataInCache();
                            }

                            if (getActiveListUpdated() && policy.getAnalyticstype().contains(CHECK_AGAINST_ACTIVELIST.name())) {
                                //LOGGER.trace("Reloading activelist cache per batch for policy that has activelist condition check");
                                functionProcessor.reloadActiveListDataInCache();
                                LOGGER.trace("[PId:{}] Size of activelist inmemory cache: {} RE:{}" ,policy.getId(), functionProcessor.getSizeOfActiveListCache(), eeo.getRawevent());
                                //setActiveListUpdated(false);
                            }

                            iefr = functionProcessor.process(eeo, policy.getId(), policy);

                            violation = iefr.isViolation();
                        }

                        policyPartsTimebyEEO.put("functionProcessor", sw2.getElapsedTimeInMilliSec());
                        sw2.reset();
                        sw2.start();

                        if (violation) {

//                            if (globalWhiteListUpdated) {
//                                LOGGER.trace("Global WhiteList  Updated updating cache");
//                                whiteListProcessor.reloadGlobalWhitelistDataIntoCache();
//                                
//                            }
                            LOGGER.info("[PId:{}] Applying whitelisting- RE:{}", entry.getKey(), eeo.getRawevent());
                            long startTimeWL = System.currentTimeMillis();
                            violation = !presentInWhiteList(eeo, entry.getValue());

                            LOGGER.trace("Policy id:{} SignatureId : {} Time taken : {}, check if key is present in whitelist", entry.getKey(), entry.getValue().getSignatureid(), (System.currentTimeMillis() - startTimeWL));
                            LOGGER.info("[PId:{}] Whitelisting result- whitelisted:{} for RE:{} ", entry.getKey(), eeo.getRawevent(), !violation);
                            policyPartsTimebyEEO.put("presentInWhiteList", sw2.getElapsedTimeInMilliSec());
                            sw2.reset();
                            sw2.start();
                            if (violation) {
                                LOGGER.trace("[PId:{}] Raw EVENT to analyze {}", policy.getId(), eeo.getRawevent());
                                if (vInfoConfig != null && !vInfoConfig.containsKey(policy.getId())) {
                                    ViolationDisplayConfigBean displayConfigBean = null;
                                    List<String> parseTemplate = null;
                                    String violationdisplayconfig = policy.getViolationdisplayconfig();
                                    if (violationdisplayconfig != null && !violationdisplayconfig.isEmpty()) {
                                        List<ViolationDisplayConfigBean> displayConfigBeans = JAXBUtilImpl.xmlToPojos(violationdisplayconfig, ViolationDisplayConfigBean.class);
                                        displayConfigBean = !displayConfigBeans.isEmpty() ? displayConfigBeans.get(0) : null;
                                    }

                                    if (policy.getVerboseinfotemplate() != null) {

                                        parseTemplate = (policy.getVerboseinfotemplate() != null && !policy.getVerboseinfotemplate().isEmpty()) ? CommonUtility.parseTemplate(policy.getVerboseinfotemplate()) : new ArrayList<>();

                                    }
                                    vInfoConfig.put(policy.getId(), new Tuple2<>(displayConfigBean, parseTemplate));

                                    LOGGER.trace("[PId:{}] vInfoConfig {}", policy.getId(), vInfoConfig);
                                }

                                policyPartsTimebyEEO.put("vInfoConfig", sw2.getElapsedTimeInMilliSec());
                                sw2.reset();
                                sw2.start();
                                LOGGER.trace("[PId:{}] GETTERS # {} AEE? {}", policy.getId(), GETTERS_PER_POLICY.get(policy.getId()), (DIRECTIVES_MAP.containsKey(policy.getId()) && DIRECTIVES_MAP.get(policy.getId())));

                                if (isAeeViolation = DIRECTIVES_MAP.containsKey(policy.getId()) && DIRECTIVES_MAP.get(policy.getId())) {

                                    aeePolicies.add(policy.getId());

                                    // this gets interesting
                                    final Map<String, Map<String, Method>> gettersPerDirective = GETTERS_PER_POLICY.get(policy.getId());

                                    final Map<String, MiniEEO> vMap = new HashMap<>();
                                    if (gettersPerDirective != null && !gettersPerDirective.isEmpty()) {
                                        LOGGER.debug("[PId:{}] Directive-enabled policy- # {}", policy.getId(), gettersPerDirective.size());
                                        final Map<String, Method> gettersForGA = gettersPerDirective.get("GA");
                                        final Map<String, Method> gettersForCA = gettersPerDirective.get("CA");

                                        String rowkey;
                                        Object attributeValue = null;

                                        rowkey = "";

                                        LOGGER.trace("[PId:{}] GA # {} CA # {}", policy.getId(), gettersForGA.size(), gettersForCA.size());
                                        if (!gettersForGA.isEmpty()) {

                                            for (Entry<String, Method> gfaEntry : gettersForGA.entrySet()) {

                                                try {
                                                    attributeValue = gfaEntry.getValue().invoke(eeo, (Object[]) null);
                                                } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException ex) {
                                                    LOGGER.error("[PId:{}] Error getting value for {}", policy.getId(), gfaEntry.getKey(), ex);
                                                    OpsLogger.log(SOURCE.IEE, SEVERITY.HIGH, String.format("[PId-%s] Error getting value for %s", policy.getId(), gfaEntry.getKey(), ex));
                                                    snyperUtil.logError(eeo.getTenantid(), eeo.getJobid(), policy.getId(), "Error getting value for " + gfaEntry.getKey());
                                                }

                                                LOGGER.trace("[PId:{}] GA Attr:{} Value:{}", policy.getId(), gfaEntry.getKey(), attributeValue);
                                                if (attributeValue != null && !attributeValue.toString().isEmpty()) { // SHOULD NOT BE NULL, IDEALLY
                                                    if (!rowkey.isEmpty()) {
                                                        rowkey += "_";
                                                    }
                                                    rowkey += attributeValue.toString();
                                                }
                                            }
                                        }

                                        final MiniEEO mEeo = new MiniEEO(eeo.getEventid(), eeo.getEventtime(), eeo.getTenantid());
                                        mEeo.setUserEncryptedFields(eeo.getU_encryptedfields());
                                        mEeo.setResourceGroupId(eeo.getRg_id());
                                        mEeo.setJobId(eeo.getJobid());
                                        mEeo.setTenantName(eeo.getTenantname());

                                        EnrichedEventObject eeoAee = new EnrichedEventObject();
                                        EEOUtil.copyEEOValuesWithoutViolations(eeo, eeoAee);

                                        mEeo.setEeo(eeoAee);

                                        if (iefr != null && iefr.getViolations() != null && iefr.getViolations().size() > 0) {
                                            Map<Long, Map<String, ViolationDetails>> vdDetails = new HashMap<>(); //set vinfo details for aee
                                            vdDetails.put(System.currentTimeMillis(), iefr.getViolations());
                                            final Violation v = new Violation(policy.getId(), policy.getName());
                                            final ViolationInfo vi = new ViolationInfo();
                                            vi.setViolationDetails(vdDetails);
                                            v.setViolationInfo(vi);
                                            mEeo.getEeo().addViolation(v);
                                            LOGGER.trace("[PId:{}] Adding violation info from iefr to AEE minieeo", policy.getId());
                                        } else {
                                            final Violation v = new Violation(policy.getId(), policy.getName());
                                            mEeo.getEeo().addViolation(v);
                                            LOGGER.trace("[PId:{}] Adding violation without iefr to AEE minieeo", policy.getId());
                                        }

                                        if (!rowkey.isEmpty()) {
                                            if (AT_LAND_SPEED.equals(policy.getAnalyticstype())) {

                                                final String ipAttribute = LAND_SPEED_IP_ATTRIBUTE.get(entry.getKey());
                                                Double latitude = null;
                                                Double longitude = null;
                                                String location = null;
                                                String nwAddress = null;

                                                if (ipAttribute != null) {
                                                    switch (ipAttribute) {
                                                        case MappedAttributeList.IPADDRESS:
                                                            latitude = eeo.getEventlatitude();
                                                            longitude = eeo.getEventlongitude();
                                                            location = getLocation(eeo.getEventcountry(), eeo.getEventcity(), eeo.getEventregion()).toString();
                                                            nwAddress = eeo.getIpaddress();
                                                            break;
                                                        case MappedAttributeList.SOURCEHOSTNAME:
                                                            latitude = eeo.getSourcehostnamelatitude();
                                                            longitude = eeo.getSourcehostnamelongitude();
                                                            location = getLocation(eeo.getSourcehostnamecountry(), eeo.getSourcehostnamecity(), eeo.getSourcehostnameregion()).toString();

                                                            nwAddress = eeo.getSourcehostname();
                                                            break;
                                                        case MappedAttributeList.DESTINATIONHOSTNAME:
                                                            latitude = eeo.getDestinationhostnamelatitude();
                                                            longitude = eeo.getDestinationhostnamelongitude();

                                                            location = getLocation(eeo.getDestinationhostnamecountry(), eeo.getDestinationhostnamecity(), eeo.getDestinationhostnameregion()).toString();

                                                            nwAddress = eeo.getDestinationhostname();
                                                            break;
                                                        case MappedAttributeList.RESOURCEHOSTNAME:
                                                            latitude = eeo.getResourcehostnamelatitude();
                                                            longitude = eeo.getResourcehostnamelongitude();
                                                            location = getLocation(eeo.getResourcehostnamecountry(), eeo.getResourcehostnamecity(), eeo.getResourcehostnameregion()).toString();

                                                            nwAddress = eeo.getResourcehostname();
                                                            break;
                                                        case MappedAttributeList.DEVICEHOSTNAME:
                                                            latitude = eeo.getDevicehostnamelatitude();
                                                            longitude = eeo.getDevicehostnamelongitude();
                                                            location = getLocation(eeo.getDevicehostnamecountry(), eeo.getDevicehostnamecity(), eeo.getDevicehostnameregion()).toString();

                                                            nwAddress = eeo.getDevicehostname();
                                                            break;
                                                    }
                                                }

                                                LOGGER.trace("[PId:{}] IpAttr:{} Lat:{} Lon:{} Loc:{} NwAddr:{}", entry.getKey(), ipAttribute, latitude, longitude, location, nwAddress);
                                                if (latitude != null && longitude != 0.0D) {
                                                    mEeo.setLatitude(latitude);
                                                    mEeo.setLongitude(longitude);
                                                    mEeo.setLocation(location);
                                                    mEeo.setNwAddress(nwAddress);
                                                    vMap.put(rowkey, mEeo);
                                                } else {
                                                    LOGGER.trace("[PId:{}] *{}* GEO ENRICHMENT NOT DONE for {}! [{}]", entry.getKey(), rowkey, ipAttribute, eeo.getRawevent());
                                                }

                                            } else {
                                                vMap.put(rowkey, mEeo);
                                            }
                                            LOGGER.trace("[PId:{}] RK:{}", entry.getKey(), rowkey);
                                        }

                                        if (!gettersForCA.isEmpty()) {

                                            for (Entry<String, Method> gfaEntry : gettersForCA.entrySet()) {

                                                try {
                                                    attributeValue = gfaEntry.getValue().invoke(eeo, (Object[]) null);
                                                } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException ex) {
                                                    LOGGER.error("[PId:{}] Error getting value for {}", policy.getId(), gfaEntry.getKey(), ex);
                                                    OpsLogger.log(SOURCE.IEE, SEVERITY.HIGH, String.format("[PId-%s] Error getting value for %s", policy.getId(), gfaEntry.getKey(), ex));
                                                    snyperUtil.logError(eeo.getTenantid(), eeo.getJobid(), policy.getId(), "Error getting value for " + gfaEntry.getKey());
                                                }

                                                LOGGER.trace("[PId:{}] CA Attr:{} Value:{}", policy.getId(), gfaEntry.getKey(), attributeValue);
                                                if (attributeValue != null && !attributeValue.toString().isEmpty()) { // SHOULD NOT BE NULL, IDEALLY
                                                    mEeo.addAttribute(gfaEntry.getKey(), attributeValue.toString());
                                                }
                                            }
                                        }

                                    } else {
                                        OpsLogger.log(SOURCE.IEE, SEVERITY.MEDIUM, String.format("[PId-%s] NO GETTERS FOR DIRECTIVES", entry.getKey()));
                                    }

                                    if (!vMap.isEmpty()) {
                                        String aeeMapKey = entry.getKey() + "_" + (policy.getResourceGroupId() == -1 ? policy.getResourceGroupId() : eeo.getRg_id());
                                        List<Map<String, MiniEEO>> aeeVList = aeeViolations.get(aeeMapKey);
                                        if (aeeVList == null) {
                                            aeeViolations.put(aeeMapKey, aeeVList = new ArrayList<>());
                                        }
                                        aeeVList.add(vMap);
                                        LOGGER.trace("[PId:{}] Added to map- {}", entry.getKey(), aeeVList.size());
                                    }
                                    policyPartsTimebyEEO.put("DIRECTIVES_MAP", sw2.getElapsedTimeInMilliSec());
                                    sw2.reset();
                                    sw2.start();

                                } else {
                                    final Violation v = new Violation(policy.getId(), policy.getName());
                                    v.setJobId(jobId);
                                    LOGGER.debug("isTier2Violation:{} PolicyId:{}", isTier2Violation, policy.getId());
                                    HashMap<Long, Map<String, ViolationDetails>> vdDetails = new HashMap<>();

                                    //No need to get riskscore and violation info for tier2 violations                                  
                                    if (isTier2Violation) {
                                        LOGGER.debug("Adding to Tier2 Violations PolicyIUd:{} iefr:{}", v.getPolicyId(), iefr);

                                        if (iefr != null) { // only when post process functions are enabled

                                            final Map<String, ViolationDetails> checksPassed = iefr.getViolations();
                                            vdDetails.put(v.getGenerationTime(), checksPassed);
                                            LOGGER.trace("[PId:{}] Checks passed # {}", policy.getId(), checksPassed.size());
                                            final ViolationInfo vi = new ViolationInfo();
                                            if (!vdDetails.isEmpty()) {
                                                vi.setViolationDetails(vdDetails);

                                                v.setViolationInfo(vi);
                                            }
                                        }

                                        tier2Violations.add(v);
                                        policyPartsTimebyEEO.put("isTier2Violation", sw2.getElapsedTimeInMilliSec());
                                        sw2.reset();
                                        sw2.start();
                                    } else {

                                        v.setViolator(policy.getViolator());
                                        v.setRiskThreatId(policy.getRiskthreatid());
                                        v.setRiskThreatName(policy.getThreatname());
                                        v.setRiskTypeId(policy.getRiskTypeId());
                                        v.setCategoryId(policy.getCategoryid());
                                        v.setCategory(policy.getCategory());
                                        
                                        double rs = com.securonix.application.policy.PolicyUtil.getPolicyScore(policy);

                                        if (iefr != null) { // only when post process functions are enabled
                                            if (iefr.getRiskScore() > 0) {
                                                rs = iefr.getRiskScore();
                                            }

                                            final Map<String, ViolationDetails> checksPassed = iefr.getViolations();
                                            vdDetails.put(v.getGenerationTime(), checksPassed);
                                            LOGGER.trace("[PId:{}] Checks passed # {}", policy.getId(), checksPassed.size());
                                        }

                                        final ViolationInfo vi = new ViolationInfo();

                                        //Deafult Violation info Forms a tree Structure
                                        String groupingAttribute = null;
                                        String lvl2Attribute = null;
                                        List<String> metaDataList = null;
                                        List<String> level2MetaDataList = null;

                                        List<String> verboseKeys = null;
                                        if (vInfoConfig != null && vInfoConfig.containsKey(policy.getId())) {
                                            Tuple2<ViolationDisplayConfigBean, List<String>> vInfoDisplayConfig = vInfoConfig.get(policy.getId());

                                            if (vInfoConfig.get(policy.getId())._1() != null) {
                                                if (vInfoDisplayConfig._1().getDisplayAttributes() != null && !vInfoDisplayConfig._1().getDisplayAttributes().isEmpty()) {
                                                    groupingAttribute = vInfoDisplayConfig._1().getDisplayAttributes().get(0);
                                                }
                                                lvl2Attribute = vInfoDisplayConfig._1().getLevel2Attributes();
                                                metaDataList = vInfoDisplayConfig._1().getMetadataAttributes();
                                                level2MetaDataList = vInfoDisplayConfig._1().getLevel2MetaDataAttr();
                                            }
                                            if (vInfoConfig.get(policy.getId())._2() != null) {
                                                verboseKeys = vInfoDisplayConfig._2();
                                            }
                                        }

                                        Map<String, Object> params = new HashMap<>();
                                        params.put(ViolationInfoConstants.FUNCTION_TYPE, ViolationInfoConstants.TREEPOLICYTYPE);
                                        params.put(ViolationDetailsTree.PARAMS.GROUP_ATTRIBUTE.name(), groupingAttribute);
                                        params.put(ViolationDetailsTree.PARAMS.LVL2_ATTRIBUTE.name(), lvl2Attribute);
                                        params.put(ViolationDetailsTree.PARAMS.METADATA_LIST.name(), metaDataList);
                                        params.put(ViolationDetailsTree.PARAMS.LVL2_METADATA.name(), level2MetaDataList);
                                        Map<String, ViolationDetails> buildViolationDetailsFromViolation = ViolationDetailsFactory.getViolationDetails(ViolationInfoConstants.TREEPOLICYTYPE, eeo, params);
                                        LOGGER.trace("Policy ID :{},buildViolationDetailsFromViolation:{}", entry.getKey(),buildViolationDetailsFromViolation);

                                        if (buildViolationDetailsFromViolation != null) {
                                            vdDetails.put(DateUtil.getScrubbedEpochTimeForDay(eeo.getTenantTz() != null ? eeo.getTenantTz() : "GMT", v.getGenerationTime()), buildViolationDetailsFromViolation);
                                        }

                                        HashMap<Long, Map<String, VerboseInfoDetails>> verboseDetails = new HashMap<>();
                                         try {
                                        verboseDetails.put(DateUtil.getScrubbedEpochTimeForDay(eeo.getTenantTz() != null ? eeo.getTenantTz() : "GMT", v.getGenerationTime()), ViolationInfoBuildUtil.buildVerbosKeyValueMap(eeo, verboseKeys));
                                        } catch (Exception ex) {
                                            LOGGER.error("Policy Id :{}, Exception", entry.getKey(), ex);
                                        }
                                        vi.setVerbosKeyValueMap(verboseDetails);

                                        vi.setViolationDetails(vdDetails);

                                        v.setViolationInfo(vi);
                                        v.setRiskScore(rs);
                                        if (isCustomViolation) {
                                            customViolations.add(v);
                                        } else {
                                            violations.add(v);
                                        }

                                        LOGGER.debug("[PId:{}] VIOLATION? (FINAL)-> {}:{}", entry.getKey(), eeo.getRawevent(), v.getRiskScore());
                                        policyPartsTimebyEEO.put("ViolationInfoBuildUtil", sw2.getElapsedTimeInMilliSec());
                                        sw2.reset();
                                        sw2.start();
                                    }
                                }

                            } else {
                                LOGGER.debug("[PId:{}] NOT A VIOLATION - as per whitelist!", entry.getKey());
                            }
                        } else {
                            LOGGER.debug("[PId:{}] NOT A VIOLATION - as per functions!", entry.getKey());
                        }
                    } else {
                        LOGGER.debug("[PId:{}] Not a violation- RE:{}", policy.getId(), eeo.getRawevent());
                    }
                    LOGGER.debug("[PId:{}] Completed .. {} [Time # {}]", policy.getId(), policy.getName(), sw.getElapsedTimeInMilliSec());
                    sw.stop();

                    policyCountTimeInLine = addPolicyTime(policyId, policy.getSignatureid(), sw.getElapsedTimeInMilliSec(), policyCountTimeInLine);

                    policyPartsTimeInLine = addPolicyTimebyBlock(policyId, policy.getSignatureid(), policyPartsTimebyEEO, policyPartsTimeInLine);
//                    if (debug) {
//                        PolicyStatsCalculator.INSTANCE.addPolicyTime(policyId.toString(), policy.getSignatureid(), sw.getElapsedTimeInMilliSec());
//                    }
                }

                LOGGER.debug("Event Completed [Time # {}]", swTotal.getElapsedTimeInMilliSec());

            } else {
                LOGGER.trace("No policies available for resource group Id {}, For EventId", resourceGroupId, eeo.getEventid());
                OpsLogger.log(SOURCE.IEE, String.format("No policies available for resource group Id- %s", resourceGroupId));
            }
        } else {
            LOGGER.debug("No policies available for {}", resourceGroupId);
        }

        LOGGER.trace("Returning intermediate violations # {}", aeeViolations);
        return aeeViolations;
    }

    /**
     *
     * @param eeo
     * @return
     */
    private static StringBuilder getLocation(String country, String eventCity, String region) {
        StringBuilder location = new StringBuilder();

        if (country != null && !country.isEmpty()) {
            location.append(country);
        }
        if (eventCity != null && !eventCity.isEmpty()) {
            location.append("|");
            location.append(eventCity);
        }

        if (region != null && !region.isEmpty()) {
            location.append("|");
            location.append(region);
        }
        return location;
    }

    /**
     * Applies filtering criteria for the policy
     *
     * @param eeo Enriched event object
     * @param groups Filtering groups
     * @param filterResult Filtering result, used during recursive call
     * @param policyId Policy Id
     * @param policyCountTimeInLine
     *
     * @return True if it matches all the filtering criteria
     */
    public boolean processGroups(final EnrichedEventObject eeo, final List<GroupBean> groups,
            final FilterResult filterResult, final long policyId, Map<String, Tuple2<Long, Long>> policyCountTimeInLine) {

        boolean error = false;
//        final List<FilterResult> frList = new ArrayList<>(); no need to track individual groups and check at the end of every group with recurssion, can do it with single object containing all results

//        String userEncryptedFields = eeo.getU_encryptedfields();
        LOGGER.trace("[PId:{}] Processing conditions (if any) ..", policyId);

        for (GroupBean group : groups) {

            LOGGER.debug("[PId:{}] Processing group .. {} -:- {} -:- {}", policyId, group.getName(), group.getConditionList(), group.getSubGroups());

            // below condition is required when all rules are deleted from a group from the UI
            if (group.getConditionList() != null || group.getSubGroups() != null) {

                final FilterResult fr = new FilterResult();

                if (group.getSubGroups() != null) {
                    filterResult.frList.add(fr); //link the results of filterresults to the previous object
                    fr.operator = group.getOperator();
                    fr.group = group.getName();
                    processGroups(eeo, group.getSubGroups(), fr, policyId, policyCountTimeInLine);
//                    frList.add(fr);
                } else {

                    final List<ConditionResult> crList = new ArrayList<>();
                    final List<ConditionBean> conditions = group.getConditionList();

                    boolean matched;
                    Object srcValue;
                    Object dstValue;
                    String condition;
                    Pattern pattern;

                    for (ConditionBean cb : conditions) {

                        matched = false;
                        Stopwatch swLHS = new Stopwatch();
                        final ConditionResult cr = new ConditionResult();

                        if (cb.getLhsOperator() != null) {
                            swLHS.reset();
                            swLHS.start();
                            LOGGER.trace("[PId:{}] Applying LHS operator ..", policyId);
                            try {

                                srcValue = processOperator((Operator) cb.getLhsOperator().clone(), eeo, policyId, 0);
                                LOGGER.info("processGroups for each LHS operator:{}, time taken:{}", cb.getLhsOperator().getType().name(), swLHS.getElapsedTimeInMilliSec());
                            } catch (OperatorException | CloneNotSupportedException ex) {
                                error = true;
                                LOGGER.error("[PId:{}] Error processing LHS operator", policyId, ex);
                                OpsLogger.log(SOURCE.IEE, SEVERITY.HIGH, String.format("[PId-%s] Error processing LHS operator", policyId, ex));
                                continue;
                            } catch (Exception ex) {
                                error = true;
                                LOGGER.error("[PId:{}] Error processing LHS operator", policyId, ex);
                                OpsLogger.log(SOURCE.IEE, SEVERITY.HIGH, String.format("[PId-%s] Error processing LHS operator", policyId, ex));
                                continue;
                            }
                        } else {
                            srcValue = EEOUtil.getEnrichedEventObjectValue(eeo, cb.getSrcField());
                            LOGGER.trace("Src Field:{}", srcValue);
                        }
                        if ((srcValue == null || srcValue.toString().isEmpty()) && !(cb.getCondition().equalsIgnoreCase(CONDITION_IS_NULL)) && !(cb.getCondition().equalsIgnoreCase(CONDITION_IS_NOT_NULL))) {
                            LOGGER.info("SrcValue object is an empty string assigning null ");
                            srcValue = "null";
                        }
                        if (cb.isCheckInLookup()) {
                            final List<String> lookUpNames = Arrays.asList(cb.getLookUpNames().split(","));
                            try {
                                StringBuilder keyMatched = new StringBuilder();

                                matched = existsInLookupTable(srcValue.toString().toUpperCase(), lookUpNames.get(0).toUpperCase(), cb.getCondition(), keyMatched, eeo.getRg_id(), cb.getSrcField());
                            } catch (Exception ex) {
                                error = true;
                                LOGGER.error("[PId:{}] Error getting value for {}", policyId, cb.getSrcField());
                                OpsLogger.log(SOURCE.IEE, SEVERITY.HIGH, String.format("[PId-%s] Error getting value for %s", policyId, cb.getSrcField()));
                                continue;
                            }
                        } else {
                            Long curr = System.currentTimeMillis();
                            if (cb.getRhsOperator() != null) {
                                LOGGER.debug("[PId:{}] Applying RHS operator ..", policyId);
                                try {
                                    Stopwatch swRHS = new Stopwatch();
                                    swRHS.reset();
                                    swRHS.start();

                                    dstValue = processOperator((Operator) cb.getRhsOperator().clone(), eeo, policyId, 0);

                                    LOGGER.info("processGroups for each RHS operator:{},Time Taken:{}", cb.getRhsOperator().getType().name(), swRHS.getElapsedTimeInMilliSec());

                                } catch (OperatorException | CloneNotSupportedException ex) {
                                    error = true;
                                    LOGGER.error("[PId:{}] Error processing RHS operator", policyId, ex);
                                    OpsLogger.log(SOURCE.IEE, SEVERITY.HIGH, String.format("[PId-%s] Error processing RHS operator", policyId, ex));
                                    continue;
                                } catch (Exception ex) {
                                    error = true;
                                    LOGGER.error("[PId:{}] Error processing RHS operator", policyId, ex);
                                    OpsLogger.log(SOURCE.IEE, SEVERITY.HIGH, String.format("[PId-%s] Error processing RHS operator", policyId, ex));
                                    continue;
                                }
                                Long time = System.currentTimeMillis() - curr;
                                policyCountTimeInLine = addPolicyTime(policyId, "WL", time, policyCountTimeInLine);

                            } else if (cb.getDestField() != null && !cb.getDestField().trim().isEmpty()) {

                                LOGGER.debug("Dest Field {}", cb.getDestField());
                                dstValue = EEOUtil.getEnrichedEventObjectValue(eeo, cb.getDestField());
//                                
                            } else {

                                dstValue = cb.getValue();
//                                
                            }
                            
                            if (dstValue ==null || dstValue.toString().isEmpty())
                            {
                                 LOGGER.info("dstValue object either null or an empty string assigning null string");
                            dstValue = "null";
                            }

                            condition = cb.getCondition();
                            /**
                             * when there are multiple values in the mapped
                             * field, check all conditions per value
                             */
                            boolean multivaluedCheck = false;
                            String[] allValues = {};
                            String dstValueUpper = dstValue != null ? dstValue.toString().toUpperCase() : "";
                            if (MULTIVALUED_ATTRIBUTES.get(eeo.getRg_id()) != null && MULTIVALUED_ATTRIBUTES.get(eeo.getRg_id()).containsKey(cb.getSrcField())) {
                                if (srcValue != null) {
                                    try {
                                        allValues = srcValue.toString().toUpperCase().split(Pattern.quote(MULTIVALUED_ATTRIBUTES.get(eeo.getRg_id()).get(cb.getSrcField())));//always check for uppercase while comparison in switch below
                                        multivaluedCheck = true;
                                    } catch (Exception ex) {
                                        LOGGER.error("Split function failed for multivalued field {}", cb.getSrcField());
                                    }
                                }
                            }

                            switch (condition) {
                                case REGEX_EQUALS:
                                    if (dstValue != null && srcValue != null) {
                                        pattern = PATTERNS.get(dstValue.toString());
                                        if (pattern == null) {
                                            try {
                                                PATTERNS.put(dstValue.toString(), pattern = Pattern.compile(dstValue.toString(), CASE_INSENSITIVE));
                                            } catch (PatternSyntaxException ex) {
                                                error = true;
                                                LOGGER.error("[PId:{}] Error parsing pattern- {} [{}]", policyId, dstValue.toString(), ex.getMessage());
                                                OpsLogger.log(SOURCE.IEE, SEVERITY.HIGH, String.format("[PId-%s] Error getting value for %s", policyId, cb.getDestField()));
                                                continue;
                                            }
                                        }
                                        if (multivaluedCheck && allValues.length > 0) {
                                            boolean multiCheckResult = false;
                                            for (String str : allValues) {
                                                if (pattern != null && pattern.matcher(str).find()) {
                                                    multiCheckResult = true;
                                                    break;
                                                }
                                            }
                                            matched = multiCheckResult;
                                        } else {
                                            matched = pattern != null && pattern.matcher(srcValue.toString()).find();
                                        }
                                    }
                                    break;

                                case REGEX_NOT_EQUALS:
                                    if (dstValue != null && srcValue != null) {
                                        pattern = PATTERNS.get(dstValue.toString());
                                        if (pattern == null) {
                                            try {
                                                PATTERNS.put(dstValue.toString(), pattern = Pattern.compile(dstValue.toString(), CASE_INSENSITIVE));
                                            } catch (PatternSyntaxException ex) {
                                                error = true;
                                                LOGGER.error("[PId:{}] Error parsing pattern- {} [{}]", policyId, dstValue.toString(), ex.getMessage());
                                                continue;
                                            }
                                        }
                                        if (multivaluedCheck && allValues.length > 0) {
                                            boolean multiCheckResult = false;
                                            for (String str : allValues) {
                                                if (pattern != null && !pattern.matcher(str).find()) {
                                                    multiCheckResult = true;
                                                } else {
                                                    multiCheckResult = false;
                                                    break;
                                                }
                                            }
                                            matched = multiCheckResult;
                                        } else {
                                            matched = pattern != null && !pattern.matcher(srcValue.toString()).find();
                                        }
                                    }
                                    break;

                                case CONDITION_EQUALS:
                                    if (multivaluedCheck && allValues.length > 0) {
                                        matched = Arrays.stream(allValues).anyMatch(str -> str != null && str.equalsIgnoreCase(dstValueUpper));
                                    } else {
                                        matched = dstValue != null && srcValue != null && dstValue.toString().equalsIgnoreCase(srcValue.toString());
                                    }

                                    try {

                                        String filedType = MappedAttributeList.EEO_TYPE_FIELD.get(cb.getSrcField());

                                        if (filedType != null && filedType.trim().length() != 0) {

                                            if (filedType.equalsIgnoreCase("DOUBLE")) {

                                                matched = Double.compare(Double.parseDouble(srcValue.toString()), Double.parseDouble(dstValue.toString())) == 0;

                                            }
                                        }

                                    } catch (Exception ex) {
                                        //ignore
                                    }

                                    /*try {
                                     if ((cb.getRhsOperator() != null && cb.getRhsOperator().getReturnType() == DATA_TYPE.DOUBLE) || ((cb.getLhsOperator() != null && cb.getLhsOperator().getReturnType() == DATA_TYPE.DOUBLE))) {
                                     matched = Double.compare(Double.parseDouble(srcValue.toString()), Double.parseDouble(dstValue.toString())) == 0;
                                     }
                                     } catch (Exception ex) {
                                     //ignore
                                     }*/
                                    break;

                                case CONDITION_NOT_EQUALS:
                                    if (multivaluedCheck && allValues.length > 0) {
                                        matched = Arrays.stream(allValues).allMatch(str -> str != null && !str.equalsIgnoreCase(dstValueUpper));
                                    } else {
                                        matched = dstValue != null && srcValue != null && !dstValue.toString().equalsIgnoreCase(srcValue.toString());
                                    }

                                    try {

                                        String filedType = MappedAttributeList.EEO_TYPE_FIELD.get(cb.getSrcField());

                                        if (filedType != null && filedType.trim().length() != 0) {

                                            if (filedType.equalsIgnoreCase("DOUBLE")) {
                                                matched = Double.compare(Double.parseDouble(srcValue.toString()), Double.parseDouble(dstValue.toString())) != 0;
                                            }
                                        }

                                    } catch (Exception ex) {
                                        //ignore
                                    }

                                    break;

                                case CONDITION_CONTAINS:
                                    if (multivaluedCheck && allValues.length > 0) {
                                        matched = Arrays.stream(allValues).anyMatch(str -> str != null && str.contains(dstValueUpper));
                                    } else {
                                        matched = dstValue != null && srcValue != null && srcValue.toString().toUpperCase().contains(dstValue.toString().toUpperCase());
                                    }
                                    break;

                                case CONDITION_DOES_NOT_CONTAIN:
                                    if (multivaluedCheck && allValues.length > 0) {
                                        matched = Arrays.stream(allValues).allMatch(str -> str != null && !str.contains(dstValueUpper));
                                    } else {
                                         LOGGER.trace("srcValue:{}", srcValue);
                                        LOGGER.trace("dstValue:{}", dstValue);
                                        if (dstValue != null && srcValue != null) {
                                            LOGGER.trace("DOES_NOT_CONTAIN:{}", !srcValue.toString().toUpperCase().contains(dstValue.toString().toUpperCase()));
                                        }
                                        matched = dstValue != null && srcValue != null && !srcValue.toString().toUpperCase().contains(dstValue.toString().toUpperCase());
                                    LOGGER.trace("DOES_NOT_CONTAIN:{}", matched);
                                    }
                                    break;

                                case CONDITION_IS_NULL:
                                    if (multivaluedCheck && allValues.length > 0) {
                                        matched = Arrays.stream(allValues).allMatch(str -> str == null || str.isEmpty());
                                    } else {
                                        matched = srcValue == null || srcValue.toString().isEmpty();
                                    }
                                    break;

                                case CONDITION_IS_NOT_NULL:
                                    if (multivaluedCheck && allValues.length > 0) {
                                        matched = Arrays.stream(allValues).allMatch(str -> str != null && !str.isEmpty());
                                    } else {
                                        matched = srcValue != null && !srcValue.toString().isEmpty();
                                    }
                                    break;

                                case CONDITION_STARTS_WITH:
                                    if (multivaluedCheck && allValues.length > 0) {
                                        matched = Arrays.stream(allValues).anyMatch(str -> str != null && str.startsWith(dstValueUpper));
                                    } else {
                                        matched = dstValue != null && srcValue != null && srcValue.toString().toUpperCase().startsWith(dstValue.toString().toUpperCase());
                                    }
                                    break;

                                case CONDITION_DOES_NOT_START_WITH:
                                    if (multivaluedCheck && allValues.length > 0) {
                                        matched = Arrays.stream(allValues).allMatch(str -> str != null && !str.startsWith(dstValueUpper));
                                    } else {
                                        matched = dstValue != null && srcValue != null && !srcValue.toString().toUpperCase().startsWith(dstValue.toString().toUpperCase());
                                    }
                                    break;

                                case CONDITION_ENDS_WITH:
                                    if (multivaluedCheck && allValues.length > 0) {
                                        matched = Arrays.stream(allValues).anyMatch(str -> str != null && str.endsWith(dstValueUpper));
                                    } else {
                                        matched = dstValue != null && srcValue != null && srcValue.toString().toUpperCase().endsWith(dstValue.toString().toUpperCase());
                                    }
                                    break;

                                case CONDITION_DOES_NOT_END_WITH:
                                    if (multivaluedCheck && allValues.length > 0) {
                                        matched = Arrays.stream(allValues).allMatch(str -> str != null && !str.endsWith(dstValueUpper));
                                    } else {
                                        matched = dstValue != null && srcValue != null && !srcValue.toString().toUpperCase().endsWith(dstValue.toString().toUpperCase());
                                    }
                                    break;

                                case CONDITION_GREATER_THAN:
                                    if (srcValue != null && dstValue != null) {
                                        try {
                                            if (multivaluedCheck && allValues.length > 0) {
                                                matched = Arrays.stream(allValues).anyMatch(str -> str != null && Double.parseDouble(str) > (Double.parseDouble(dstValueUpper)));
                                            } else {
                                                matched = Double.parseDouble(srcValue.toString()) > Double.parseDouble(dstValue.toString());
                                            }
                                        } catch (NumberFormatException ex) {
                                            matched = false;
                                            LOGGER.error("[PId:{}] Error parsing one of the values- {}:{}", policyId, srcValue.toString(), dstValue.toString());
                                        }
                                    }
                                    break;

                                case CONDITION_LESS_THAN:
                                    if (srcValue != null && dstValue != null) {
                                        try {
                                            if (multivaluedCheck && allValues.length > 0) {
                                                matched = Arrays.stream(allValues).anyMatch(str -> str != null && Double.parseDouble(str) < (Double.parseDouble(dstValueUpper)));
                                            } else {
                                                matched = Double.parseDouble(srcValue.toString()) < Double.parseDouble(dstValue.toString());
                                            }
                                        } catch (NumberFormatException ex) {
                                            matched = false;
                                            LOGGER.error("[PId:{}] Error parsing one of the values- {}:{}", policyId, srcValue.toString(), dstValue.toString());
                                        }
                                    }
                                    break;

                                case CONDITION_GREATER_THAN_OR_EQUALS:
                                    if (srcValue != null && dstValue != null) {
                                        try {
                                            if (multivaluedCheck && allValues.length > 0) {
                                                matched = Arrays.stream(allValues).anyMatch(str -> str != null && Double.parseDouble(str) >= (Double.parseDouble(dstValueUpper)));
                                            } else {
                                                matched = Double.parseDouble(srcValue.toString()) >= Double.parseDouble(dstValue.toString());
                                            }
                                        } catch (NumberFormatException ex) {
                                            matched = false;
                                            LOGGER.error("[PId:{}] Error parsing one of the values- {}:{}", policyId, srcValue.toString(), dstValue.toString());
                                        }
                                    }
                                    break;

                                case CONDITION_LESS_THAN_OR_EQUALS:
                                    if (srcValue != null && dstValue != null) {
                                        try {
                                            if (multivaluedCheck && allValues.length > 0) {
                                                matched = Arrays.stream(allValues).anyMatch(str -> str != null && Double.parseDouble(str) <= (Double.parseDouble(dstValueUpper)));
                                            } else {
                                                matched = Double.parseDouble(srcValue.toString()) <= Double.parseDouble(dstValue.toString());
                                            }
                                        } catch (NumberFormatException ex) {
                                            matched = false;
                                            LOGGER.error("[PId:{}] Error parsing one of the values- {}:{}", policyId, srcValue.toString(), dstValue.toString());
                                        }
                                    }
                                    break;

                                default:
                                    LOGGER.trace("[PId:{}] Invalid condition- {}", policyId, condition);
                                    OpsLogger.log(SOURCE.IEE, SEVERITY.MEDIUM, String.format("[PId-%s] Invalid condition- %s", policyId, condition));
                                    matched = false;
                                    break;
                            }

                            if (srcValue == null && !condition.equals(CONDITION_IS_NULL)) {
                                matched = false;
                            }

                            cr.dstValue = dstValue == null || dstValue.toString().isEmpty() ? null : dstValue.toString();
                            LOGGER.trace(" DST VALUE :{}", cr.dstValue);
                            cr.condition = condition;
                        }

                        cr.result = matched;
                        cr.operator = cb.getLogicalCondition();
                        cr.srcValue = srcValue == null || srcValue.toString().isEmpty() ? null : srcValue.toString();
                        LOGGER.trace("SRC VALUE:{}", cr.srcValue);

                        crList.add(cr);

                        LOGGER.debug("[PId:{}] GRP:{} Src:{} {} Dst:{} = {} [{}] ALC:{} AL:{}", policyId, group.getName(), srcValue,
                                cr.condition, cr.dstValue, matched, cb.getLogicalCondition(), cb.isCheckInActiveList(), cb.getActiveLists());
                    }

                    matched = false;
                    Boolean prevMatch = null;
                    String operator = "";
                    for (ConditionResult cr : crList) {

                        LOGGER.debug("[PId:{}] Srcvalue: {} condition: {} Dstvalue: {} cr operator: {} result: {} operator:{}", policyId, cr.srcValue, cr.condition, cr.dstValue, cr.operator, cr.result, operator);
                        // this is first record
                        if (prevMatch == null) {
                            prevMatch = cr.result;
                            matched = cr.result;
                        } else {
                            if (operator != null && !operator.equals("")) {
                                switch (operator) {
                                    case OR:
                                        matched = prevMatch || cr.result;
                                        LOGGER.debug("[PId:{}] {}:{}:{}:{}", policyId, operator, prevMatch, cr.result, matched);
                                        break;
                                    case AND:
                                        matched = prevMatch && cr.result;
                                        LOGGER.debug("[PId:{}] {}:{}:{}:{}", policyId, operator, prevMatch, cr.result, matched);
                                        break;
                                }
                            } else {
                                LOGGER.warn("[PId:{}] Operator is null or empty", policyId);
                            }
                        }

                        LOGGER.debug("[PId:{}] prevMatch:{} matched:{}", policyId, prevMatch, matched);
                        operator = cr.operator;
                        prevMatch = matched;
                    }

                    LOGGER.debug("[PId:{}] GRP:{} Matched:{}", policyId, group.getName(), matched);
                    fr.group = group.getName();
                    fr.result = matched;
                    fr.operator = group.getOperator();

                    if (filterResult != null) {
                        LOGGER.debug("[PId:{}] This is nested group # {}", policyId, filterResult.frList.size());
                        filterResult.frList.add(fr); //keep linking objects to the previous filterresult
                    } else {
//                        frList.add(fr); why does it ever have to be null???
                    }
                }
            }
        }

        boolean matched = false;

        if (groups == null || groups.isEmpty()) {
            matched = true; // it's a violation when no conditions are specified
        } else if (!error) {
//            LOGGER.debug("[PId:{}] FR LIST # {}", policyId, frList.size()); // no need to check for the findresults using recurssion here instead do it at the end, outside this function, since this itself is recurssion
//            if (!frList.isEmpty()) {
//                matched = findResult(policyId, frList);
//                LOGGER.debug("[PId:{}] FINALLY MATCHED? {}", policyId, matched);
//            } else {
//                matched = true;
//            }
            matched = true;
        }

        return matched;
    }

    public static void clearLookups(final Set<String> tables) {
        tables.forEach(table -> {
            SYSTEM_LOOKUP_MAP.remove(table);
            LOGGER.trace("Lookup table entry removed! {}", table);
        });
    }

    private static final Map<String, Map<String, Map<String, Object>>> SYSTEM_LOOKUP_MAP = new ConcurrentHashMap<>();

    private final static Map<String, LookUpCoreBean> LOOKUP_CACHE = new ConcurrentHashMap<>();

    public static void populateLookupResults(Map<String, Object> map, String key, List<LookUpCoreBean> matchedRows, StringBuilder keyMatched) {
        Map<String, String> fieldValueMap = new HashMap<>();
        for (Map.Entry<String, Object> entrySet : map.entrySet()) {
            if (entrySet.getValue() != null || !entrySet.getValue().toString().isEmpty()) {
                fieldValueMap.put(entrySet.getKey(), entrySet.getValue().toString());
            }
        }
        LookUpCoreBean lookUpCoreBean = new LookUpCoreBean();
        lookUpCoreBean.setKey(key);
        lookUpCoreBean.setValueMap(fieldValueMap);

        matchedRows.add(lookUpCoreBean);
        keyMatched.append(lookUpCoreBean.getKey());
        LOGGER.trace("matchedRows:{},keyMatched:{}", matchedRows, keyMatched);
        LOOKUP_CACHE.put(key, lookUpCoreBean);
        LOGGER.trace("Key {} updated in cache!", key);
    }

    public boolean existsInLookupTable(String searchString, String lookUpTableName, String searchMethod, StringBuilder keyMatched, long rgId, String searchStringAttribute) {

        Map<String, String> rowSearchAfterAppend = new HashMap<>();
        LOGGER.trace("Input :searchString -{}, lookUpTableName -{}, searchMethod -{}, keyMatched -{}, searchStringAttribute-{} , rgId-{}", searchString, lookUpTableName, searchMethod, keyMatched, searchStringAttribute, rgId);

        long tenant = lookupNameWithTenantId.get(lookUpTableName) != null ? lookupNameWithTenantId.get(lookUpTableName) : -1l;
        final String lookupTableNameKey = tenant + HEADERDELIMITER + SOURCELOOKUP + HEADERDELIMITER + lookUpTableName;
        LOGGER.trace("The lookupkey value formed along with tenantid is {}", lookupTableNameKey);
        final boolean systemLookup = IEFunctionSingleton.INSTANCE.isSystemLookupTable(lookupTableNameKey);
        LOGGER.trace("LTN:{} IsSystemLookup? {}", lookupTableNameKey, systemLookup);

        Map<String, Map<String, Object>> lookupTable = null;

        if (systemLookup) {
            long currTimeInList = System.currentTimeMillis();
            lookupTable = SYSTEM_LOOKUP_MAP.get(lookupTableNameKey);
            if (lookupTable == null) {
                LOGGER.trace("Loading system lookup table from REDIS .. {}", lookupTableNameKey);
                lookupTable = IEFunctionSingleton.INSTANCE.getLookupTable(lookupTableNameKey);//Redis call
                SYSTEM_LOOKUP_MAP.put(lookupTableNameKey, lookupTable);
                LOGGER.trace("Lookup table keys # {}", lookupTable.size());
            }
        LOGGER.info("LOADED lookupTable IN LIST from Redis"+lookupTableNameKey+" memory time(ms): "+(System.currentTimeMillis() - currTimeInList)+"Size"+lookupTable.size()+"time loaded in epoch"+System.currentTimeMillis());
        }

        Set<String> lookupKeys = lookupTable == null ? new HashSet<>() : lookupTable.keySet();
        List<LookUpCoreBean> matchedRows = new ArrayList<>();
        boolean multivaluedCheck = false;
        String[] allValues = {};
        byte[] bytes;
        if (MULTIVALUED_ATTRIBUTES.containsKey(rgId) && MULTIVALUED_ATTRIBUTES.get(rgId).containsKey(searchStringAttribute)) {
            allValues = searchString.split(Pattern.quote(MULTIVALUED_ATTRIBUTES.get(rgId).get(searchStringAttribute)));
            multivaluedCheck = true;
        }
        LOGGER.trace("[MultivaluedCheck value is {}]", multivaluedCheck);
        synchronized (matchedRows) {

            switch (searchMethod) {
                case CONDITION_EQUALS_IN_LIST:
                    if (multivaluedCheck) {
                        for (String str : allValues) {
                            if (checkEqualsCondition(str, lookupTableNameKey, systemLookup, lookupTable, matchedRows, keyMatched)) {
                                break;
                            }
                        }

                    } else {
                        checkEqualsCondition(searchString, lookupTableNameKey, systemLookup, lookupTable, matchedRows, keyMatched);
                        LOGGER.trace("[Lookup table type system ?: {}] [search : {} ]", systemLookup, searchString);

                    }
                    break;
                case CONDITION_CONTAINS_IN_LIST:
                    if (multivaluedCheck) {
                        for (String str : allValues) {

                            checkContainsInListCondition(str, lookupTableNameKey, systemLookup, lookupKeys, lookupTable, matchedRows, keyMatched);

                        }

                    } else {

                        checkContainsInListCondition(searchString, lookupTableNameKey, systemLookup, lookupKeys, lookupTable, matchedRows, keyMatched);

                    }

                    break;

                case CONDITION_DOES_NOT_CONTAIN_IN_LIST:
                    Stopwatch sw_IN_LIST = new Stopwatch();
                    sw_IN_LIST.reset();
                    sw_IN_LIST.start();
                    if (multivaluedCheck) {
                        for (String str : allValues) {
                            if (systemLookup) {
                                try {
                                    for (String rKey : lookupKeys) {
                                        if (!str.contains(rKey)) {
                                            Map<String, Object> map = lookupTable.get(rKey);
                                            populateLookupResults(map, rKey, matchedRows, keyMatched);
                                        }
                                    }
                                } catch (Exception ex) {
                                    LOGGER.error(ex);
                                }
                            } else {

                                Set<String> tableKeys = redisClient.getKeys(lookupTableNameKey + "*", RedisNamespaceConstants.LOOKUP);
                                String keyShouldNotContain = lookupTableNameKey + "|" + str;
                                tableKeys.remove(keyShouldNotContain);

                                try {
                                    for (String rKey : tableKeys) {
                                        Map<String, Object> map = SERIALIZER.deserialize(redisClient.getValue(rKey.getBytes(), RedisNamespaceConstants.LOOKUP));
                                        LOGGER.trace("map", map.toString());
                                        populateLookupResults(map, rKey, matchedRows, keyMatched);
                                    }
                                } catch (Exception ex) {
                                    LOGGER.error(ex);
                                }
                            }
                        }

                    } else if (systemLookup) {
                        try {
                            for (String rKey : lookupKeys) {

                                if (!searchString.contains(rKey)) {
//if (!lookupKeys.contains(searchString)) {
                                    Map<String, Object> map = lookupTable.get(rKey);
                                    LOGGER.trace("VK-map:{},key:{},matchedRows:{},keyMatched:{}", map, rKey, matchedRows, keyMatched);
                                    populateLookupResults(map, rKey, matchedRows, keyMatched);

                                }
                            }
                        } catch (Exception ex) {
                            LOGGER.error(ex);
                        }
                    }
//                    else {
//                            
//                        Set<String> tableKeys = redisClient.getKeys(lookupTableNameKey + "*", RedisNamespaceConstants.LOOKUP);
//
//                        String keyShouldNotContain = lookupTableNameKey + "|" + searchString;
//                        tableKeys.remove(keyShouldNotContain);
//
//                        try {
//                            for (String rKey : tableKeys) {
//                                Map<String, Object> map = SERIALIZER.deserialize(redisClient.getValue(rKey.getBytes(), RedisNamespaceConstants.LOOKUP));
//                                populateLookupResults(map, rKey, matchedRows, keyMatched);
//                            }
//                        } catch (Exception ex) {
//                            LOGGER.error(ex);
//                        }
//                    }

                    LOGGER.trace("Time taken for DOESNOTCONTAIN_IN_LIST:{}", sw_IN_LIST.getElapsedTimeInMilliSec());
                    break;
                case CONDITION_STARTS_WITH_IN_LIST:
                    if (multivaluedCheck) {
                        for (String str : allValues) {
                            String prefix = lookupTableNameKey + "|" + str;

                            if (systemLookup) {
                                try {
                                    for (String rKey : lookupKeys) {
                                        if (rKey.startsWith(str)) {
                                            Map<String, Object> map = lookupTable.get(rKey);
                                            populateLookupResults(map, rKey, matchedRows, keyMatched);
                                        }
                                    }
                                } catch (Exception ex) {
                                    LOGGER.error(ex);
                                }
                            } else {
                                Set<String> keysStartWith = redisClient.getKeys(prefix + "*", RedisNamespaceConstants.LOOKUP);
                                try {
                                    for (String rKey : keysStartWith) {
                                        Map<String, Object> map = SERIALIZER.deserialize(redisClient.getValue(rKey.getBytes(), RedisNamespaceConstants.LOOKUP));
                                        populateLookupResults(map, rKey, matchedRows, keyMatched);
                                    }
                                } catch (Exception ex) {
                                    LOGGER.error(ex);
                                }
                            }
                        }
                    } else {
                        String prefix = lookupTableNameKey + "|" + searchString;

                        if (systemLookup) {
                            try {
                                for (String rKey : lookupKeys) {
                                    if (searchString.startsWith(rKey)) {
                                        Map<String, Object> map = lookupTable.get(rKey);
                                        populateLookupResults(map, rKey, matchedRows, keyMatched);
                                    }
                                }
                            } catch (Exception ex) {
                                LOGGER.error(ex);
                            }
                        } else {
                            Set<String> keysStartWith = redisClient.getKeys(prefix + "*", RedisNamespaceConstants.LOOKUP);
                            try {
                                for (String rKey : keysStartWith) {
                                    Map<String, Object> map = SERIALIZER.deserialize(redisClient.getValue(rKey.getBytes(), RedisNamespaceConstants.LOOKUP));
                                    populateLookupResults(map, rKey, matchedRows, keyMatched);
                                }
                            } catch (Exception ex) {
                                LOGGER.error(ex);
                            }
                        }
                    }
                    break;
                case CONDITION_ENDS_WITH_IN_LIST:
                    if (multivaluedCheck) {

                        for (String str : allValues) {

                            String postfix = lookupTableNameKey + "|" + "*" + str;

                            if (systemLookup) {
                                try {
                                    for (String rKey : lookupKeys) {
                                        if (rKey.endsWith(str)) {
                                            Map<String, Object> map = lookupTable.get(rKey);
                                            populateLookupResults(map, rKey, matchedRows, keyMatched);
                                        }
                                    }
                                } catch (Exception ex) {
                                    LOGGER.error(ex);
                                }
                            } else {
                                Set<String> keysEndWith = redisClient.getKeys(postfix, RedisNamespaceConstants.LOOKUP);
                                try {
                                    for (String rKey : keysEndWith) {
                                        Map<String, Object> map = SERIALIZER.deserialize(redisClient.getValue(rKey.getBytes(), RedisNamespaceConstants.LOOKUP));
                                        populateLookupResults(map, rKey, matchedRows, keyMatched);

                                    }
                                } catch (Exception ex) {
                                    LOGGER.error(ex);
                                }
                            }
                        }
                    } else {

                        String postfix = lookupTableNameKey + "|" + "*" + searchString;

                        if (systemLookup) {
                            try {
                                for (String rKey : lookupKeys) {
                                    if (searchString.endsWith(rKey)) {
                                        Map<String, Object> map = lookupTable.get(rKey);
                                        populateLookupResults(map, rKey, matchedRows, keyMatched);
                                    }
                                }
                            } catch (Exception ex) {
                                LOGGER.error(ex);
                            }
                        } else {
                            Set<String> keysEndWith = redisClient.getKeys(postfix, RedisNamespaceConstants.LOOKUP);
                            try {
                                for (String rKey : keysEndWith) {
                                    Map<String, Object> map = SERIALIZER.deserialize(redisClient.getValue(rKey.getBytes(), RedisNamespaceConstants.LOOKUP));
                                    populateLookupResults(map, rKey, matchedRows, keyMatched);

                                }
                            } catch (Exception ex) {
                                LOGGER.error(ex);
                            }
                        }
                    }
                    break;
                case CONDITION_NOT_EQUALS_IN_LIST:
                    if (multivaluedCheck) {
                        for (String str : allValues) {
                            if (str != null && !str.isEmpty()) {
                                String key = lookupTableNameKey + "|" + str;
                                LOGGER.trace("[Lookup table type system ?: {}] [search : {} ]", systemLookup, str);
                                if (systemLookup) {

                                    if (!lookupTable.containsKey(str)) { //never matches

                                        Map<String, Object> map = new HashMap<>();
                                        populateLookupResults(map, key, matchedRows, keyMatched);

                                        LOGGER.trace("Found System lookup match key {} search {} val map {}  ", key, str, map);
                                        break;
                                    }
                                } else {
                                    LookUpCoreBean lucb = LOOKUP_CACHE.get(key);
                                    if (lucb == null) {
                                        if ((bytes = redisClient.getValue(key.getBytes(), RedisNamespaceConstants.LOOKUP)) != null) {
                                            break;
                                        } else {
                                            Map<String, Object> map = new HashMap<>();
                                            populateLookupResults(map, key, matchedRows, keyMatched);
                                            LOGGER.trace("Redis Query Done and key not found:{}", key);

                                        }
                                    } else {
                                        LOGGER.trace("Found key {} in cache!", key);
                                        break;
                                    }

                                }
                            }
                        }

                    } else {
                        String key = lookupTableNameKey + "|" + searchString;
                        LOGGER.trace("[Lookup table type system ?: {}] [search : {} ]", systemLookup, searchString);
                        if (systemLookup) {

                            if (!(lookupTable.containsKey(searchString))) { //never matches

                                Map<String, Object> map = new HashMap<>();
                                populateLookupResults(map, key, matchedRows, keyMatched);

                                LOGGER.trace("Found System lookup match key {} search {} map {}  ", key, searchString, map);
                            }
                        } else {
                            LookUpCoreBean lucb = LOOKUP_CACHE.get(key);
                            if (lucb == null) {
                                if ((bytes = redisClient.getValue(key.getBytes(), RedisNamespaceConstants.LOOKUP)) != null) {
                                    break;
                                } else {
                                    Map<String, Object> map = new HashMap<>();
                                    populateLookupResults(map, key, matchedRows, keyMatched);
                                    LOGGER.info("Redis Query Done and key not found:{}", key);

                                }
                            } else {
                                LOGGER.info("Found key {} in cache!", key);
                            }
                        }
                    }
                    break;
                default:
                    LOGGER.error("searchMethod -{} is not supported", searchMethod);
                    return false;
            }
        }

        LOGGER.debug("matchedRows-----{}", matchedRows);
        LOGGER.trace("rowSearchAfterAppend" + rowSearchAfterAppend);

        if (rowSearchAfterAppend.isEmpty()) {
            if (searchMethod.equals(CONDITION_DOES_NOT_CONTAIN_IN_LIST)) {
//                Set<String> tableKeys = redisClient.getKeys(lookupTableNameKey + "*", RedisNamespaceConstants.LOOKUP);            
                return matchedRows.size() == lookupTable.size();//tableKeys.size()
            } else {
                return !matchedRows.isEmpty();
            }
        }

        return true;
    }

    private void checkContainsInListCondition(String str, final String lookupTableNameKey, final boolean systemLookup, Set<String> lookupKeys, Map<String, Map<String, Object>> lookupTable, List<LookUpCoreBean> matchedRows, StringBuilder keyMatched) {
        if (str != null && !str.isEmpty()) {

            String key = lookupTableNameKey + "|" + "*" + str + "*";

            if (systemLookup) {
                try {
                    for (String rKey : lookupKeys) {
                        if (str.contains(rKey)) {
                            Map<String, Object> map = lookupTable != null ? lookupTable.get(rKey) : new HashMap<>();
                            populateLookupResults(map, rKey, matchedRows, keyMatched);
                            break;
                        }
                    }
                } catch (Exception ex) {
                    LOGGER.error(ex);
                }
            } else {
                LookUpCoreBean lucb = LOOKUP_CACHE.get(key);
                if (lucb == null) {
                    Set<String> keys = redisClient.getKeys(key, RedisNamespaceConstants.LOOKUP);
                    if (!keys.isEmpty()) {
                        try {
                            for (String rKey : keys) {
                                Map<String, Object> map = SERIALIZER.deserialize(redisClient.getValue(rKey.getBytes(), RedisNamespaceConstants.LOOKUP));
                                populateLookupResults(map, rKey, matchedRows, keyMatched);
                            }
                        } catch (Exception ex) {
                            LOGGER.error(ex);
                        }
                    } else {
                        LOGGER.trace("Redis Query Done and key not found:{}", key);

                    }
                } else {
                    LOGGER.trace("Found key {} in cache!", key);
                    keyMatched.append(lucb.getKey());
                    matchedRows.add(lucb);
                }

            }

        }
    }

    private boolean checkEqualsCondition(String str, final String lookupTableNameKey, final boolean systemLookup, Map<String, Map<String, Object>> lookupTable, List<LookUpCoreBean> matchedRows, StringBuilder keyMatched) {
        byte[] bytes;
        if (str != null && !str.isEmpty()) {
            String key = lookupTableNameKey + "|" + str;
            LOGGER.trace("[Lookup table type system ?: {}] [search : {} ]", systemLookup, str);
            if (systemLookup) {
                if (lookupTable.containsKey(str)) {
                    //matched

                    Map<String, Object> map = lookupTable.get(str);
                    populateLookupResults(map, key, matchedRows, keyMatched);
                    LOGGER.trace("Found System lookup match key {} search {} val map {}  ", key, str, map);
                    return true;
                }
            } else {
                LookUpCoreBean lucb = LOOKUP_CACHE.get(key);
                if (lucb == null) {
                    if ((bytes = redisClient.getValue(key.getBytes(), RedisNamespaceConstants.LOOKUP)) != null) {
                        try {
                            final Map<String, Object> map = SERIALIZER.deserialize(bytes);
                            populateLookupResults(map, key, matchedRows, keyMatched);
                            return true;
                        } catch (Exception ex) {
                            LOGGER.error(ex);
                        }
                    } else {
                        LOGGER.trace("Redis Query Done and key not found:{}", key);
                    }
                } else {
                    LOGGER.trace("Found key {} in cache!", key);
                    keyMatched.append(lucb.getKey());
                    matchedRows.add(lucb);
                    return true;
                }
            }
        }
        return false;
    }

    public boolean findResult(final long policyId, final List<FilterResult> frList) {

        LOGGER.trace("[PId:{}] FRList empty? {}", policyId, frList.isEmpty());

        boolean matched = true;
        if (!frList.isEmpty()) {

            String operator = null;
            for (FilterResult fr : frList) {

                if (!fr.frList.isEmpty()) {
                    LOGGER.trace("[PId:{}] list size {} group {} matched state so far{}", policyId, fr.frList.size(), fr.group, matched);
                    if (operator == null || AND.equals(operator)) { // first record //treat null as AND condition
                        matched = matched && findResult(policyId, fr.frList);
                    } else {
                        // it is OR now
                        matched = matched || findResult(policyId, fr.frList);
                    }
                } else {

                    LOGGER.trace("[PId:{}] GRP:{} FR-OP:{} RES:{} OP:{}", policyId, fr.group, fr.operator, fr.result, operator);
                    if (operator == null || AND.equals(operator)) { // first record //treat null as AND condition
                        matched = matched && fr.result;
                    } else {
                        // it is OR now
                        matched = matched || fr.result;
                    }
                }
                LOGGER.trace("[PId:{}] This stage evaluation {}, operator for next stage {} ", policyId, matched, fr.operator);
                operator = fr.operator;
            }
        }

        return matched;
    }

    /**
     * returns result from the findResult of the, findResult(final long
     * policyId, final List<FilterResult> frList)
     *
     * @param policyId
     * @param filterResult
     * @return
     */
    public boolean findResult(final long policyId, final FilterResult filterResult) {
        return findResult(policyId, filterResult.frList);
    }

    /**
     * Class to hold final result for a group
     */
    public class FilterResult {

        String group;
        boolean result;
        String operator;
        final List<FilterResult> frList = new ArrayList<>();
    }

    /**
     * Class to hold the result of conditions
     */
    private class ConditionResult {

        boolean result;
        String operator;
        String srcValue;
        String dstValue;
        String condition;
    }

    public boolean isProcessGroupsViolation(final EnrichedEventObject eeo, final List<GroupBean> groups,
            FilterResult filterResult, final long policyId, Map<String, Tuple2<Long, Long>> policyCountTimeInLine) {
        if (filterResult == null) {
            filterResult = new FilterResult();
        }
        processGroups(eeo, groups, filterResult, policyId, policyCountTimeInLine);
        return findResult(policyId, filterResult.frList);
    }

    private Object processOperator(final Operator operator, final EnrichedEventObject eeo,
            final long policyId, final int level) throws OperatorException {

        ParameterInfo parameterInfo = operator.getParameterInfo();
        List<Parameter> paramsType = parameterInfo.getParameters();

        String userEncryptedFields = eeo.getU_encryptedfields();

        LOGGER.debug("[PId:{}] Processing operator- {}", policyId, operator.getType().name());
        final List<Object> updatedParameters = new ArrayList<>();
        final List<Object> parameters = operator.getParameters();
 Operator.DATA_TYPE dType = null;
        for (Object o : parameters) {
            LOGGER.trace("[PId:{}] (ORIG) LEVEL-{}:{}", policyId, level, o.toString());
        }

        String param;
        String attribute;

        int i = 0;

        for (Object o : parameters) {

            LOGGER.debug("[PId:{}] Instance- {}", policyId, o.getClass());
            if (o instanceof String) {
                String value = null;

                param = (String) o;
                LOGGER.debug("[PId:{}] Attribute- {}", policyId, param);
                if (param.startsWith("eeo.") || param.startsWith("EEO.")) {
                    attribute = param.substring(4);
                        Object enrichedEventObjectValue = EEOUtil.getEnrichedEventObjectValue(eeo, attribute);
                        value = enrichedEventObjectValue != null ? enrichedEventObjectValue.toString() : null;

                        if (value == null) {
                            LOGGER.trace("Value not available for the attribute" + attribute);
                        }
                        LOGGER.debug("[PId:{}] Attr-{} Value={}", policyId, attribute, value);
                   LOGGER.trace("paramsType.size():{}", paramsType.size());
                    if( i < paramsType.size()) {
                     dType = paramsType.get(i).getType();
                    }

                    i++;

                    LOGGER.trace("Value -{} and paramtype -{}", value, dType);
                    try {
                        if (dType == DATA_TYPE.LONG) {
                            updatedParameters.add(Long.parseLong(value));
                        } else if (dType == DATA_TYPE.FLOAT) {
                            updatedParameters.add(Float.parseFloat(value));
                        } else if (dType == DATA_TYPE.INT) {
                            updatedParameters.add(Integer.parseInt(value));
                        } else if (dType == DATA_TYPE.DOUBLE) {
                            updatedParameters.add(Double.parseDouble(value));
                        } else {
                            updatedParameters.add(value);
                        }
                    } catch (Exception ex) {
                        LOGGER.error("Skipping Operator:{}, Value-{}, Paramtype-{} /n Exception:{}",operator.getType(),value,dType,ex);
                        continue;
                    }
                } else {
                    updatedParameters.add(param);
                }
            } else if (o instanceof Operator) {
                try {
                    processOperator((Operator) (o = ((Operator<Object>) o).clone()), eeo, policyId, 1);
                } catch (CloneNotSupportedException ex) {
                } catch (Exception ex) {
                    LOGGER.error("[PId:{}] Error processing  operator", policyId, ex);
                }
                updatedParameters.add(o);
            } else {
                updatedParameters.add(o);
            }
        }

        LOGGER.debug("[PId:{}] Processing operator now .. {}", policyId, operator.getType().name());
        operator.setParameters(updatedParameters);

        for (Object o : updatedParameters) {
            if (o != null) {
                LOGGER.trace("[PId:{}] (REPLACED) LEVEL-{}:{}", policyId, level, o.toString());
            }
        }

        if (updatedParameters.isEmpty()) {
            return null;
        }

        switch (operator.getType()) {

            case WHITELIST_FILTER: {
                if (alexa == null) {
                    long currTime_whitelistfilter = System.currentTimeMillis();
                    alexa = ProxyWhiteListDomainLoader.INSTANCE.getAlexa();
                    LOGGER.info("LOADED 1 M from HDFS memory time( in ms): " +(System.currentTimeMillis() - currTime_whitelistfilter)+ "time loaded in epoch"+System.currentTimeMillis());
 
                }
                
                updatedParameters.add(alexa.getDomains());
                break;
            }

            case WHITELISTIP: {

                if (whiteListedIps == null) {
                    Stopwatch swWhiteListIP = new Stopwatch();
                    swWhiteListIP.reset();
                    swWhiteListIP.start();

                    whiteListedIps = new WhiteListedIps(hcb);

                    LOGGER.debug("Event Completed [Time # {}]", swWhiteListIP.getElapsedTimeInMilliSec());

                }
                updatedParameters.add(whiteListedIps.getWhitelistedIps());
                break;

            }
        }

        return level == 0 ? operator.operate() : null;
    }

    public boolean presentInWhiteList(EnrichedEventObject eeo, PolicyMaster pm) {
        LOGGER.trace("GlobalWhiteListUpdated:{}", getGlobalWhiteListUpdated());
        Boolean globalWhiteListUpdated = getGlobalWhiteListUpdated();
        Boolean whiteListExists = whiteListProcessor.presentInWhiteListInMemory(eeo, pm, globalWhiteListUpdated);
        setGlobalWhiteListUpdated(false);
        LOGGER.trace("setGlobalWhiteListUpdated:{}", globalwhitelistUpdated);
        return whiteListExists;
    }

    public void addNewWhitelistAttributeKeys(final Set<String> newAttributeEntries) {
        this.whiteListProcessor.addKeysToRedisKeysCache(newAttributeEntries);
        LOGGER.trace("Whitelists attribute key added - {}", newAttributeEntries);
    }

    public void removeExpiredWhitelistAttributeKeys(final Set<String> expiredAttributeEntries) {
        this.whiteListProcessor.removeKeysFromRedisKeysCache(expiredAttributeEntries);
        LOGGER.trace("Whitelists attribute key removed - {}", expiredAttributeEntries);
    }

    public void addWhitelistEntryForPolicyorFunctionaltiy(final Set<String> newAttributeEntries) {
        this.whiteListProcessor.addWhitelistEntryForPolicyorFunctionaltiy(newAttributeEntries);
        LOGGER.trace("new whitelist added - {}", newAttributeEntries);
    }

    public void removeWhitelistEntryForPolicyorFunctionaltiy(final Set<String> newAttributeEntries) {
        this.whiteListProcessor.removeWhitelistEntryForPolicyorFunctionaltiy(newAttributeEntries);
        LOGGER.trace("whitelist removed- {}", newAttributeEntries);
    }

    public WhiteListProcessor getWhiteListProcessor() {
        return whiteListProcessor;
    }

    public FilterResult groupResultsTest;

    public IEProcessor() { //this is to be used for testing only
        hcb = null;
        updateCounts = false;
        groupResultsTest = new FilterResult();

    }

    public Boolean getTpiUpdated() {
        return tpiUpdated;
    }

    public void setTpiUpdated(Boolean tpiUpdated) {
        this.tpiUpdated = tpiUpdated;
    }

    public Boolean getLookupUpdated() {
        return lookupUpdated;
    }

    public void setLookupUpdated(Boolean lookupUpdated) {
        this.lookupUpdated = lookupUpdated;
    }

    public Boolean getActiveListUpdated() {
        return activelistUpdated;
    }

    public void setActiveListUpdated(Boolean activelistUpdated) {
        this.activelistUpdated = activelistUpdated;
    }
 public Boolean getGlobalWhiteListUpdated() {
        return globalwhitelistUpdated;
    }

    public void setGlobalWhiteListUpdated(Boolean globalwhiteListUpdated) {
        this.globalwhitelistUpdated = globalwhiteListUpdated;
    }

    public static void main(String[] args) throws Exception {

        LOGGER.debug("Testing now ..");

        HBaseConfigBean hcb = new HBaseConfigBean();
        hcb.setAuthType(HadoopConfigBean.AUTHENTICATION_TYPE.NOAUTH);
        hcb.setNamespace("sudhanshu");
        hcb.addResource("file:///etc/hbase/conf/hbase-site.xml");
        hcb.addResource("file:///etc/hbase/conf/core-site.xml");

        HBaseClient hc = new HBaseClient();
        hc.initializeHBase(hcb);
        LOGGER.debug("HBase client initialized? {}", hc.isInitialized());

        KafkaConfigBean kcb = new KafkaConfigBean();
        ZookeeperConfigBean zcb = new ZookeeperConfigBean();

//        kcb.setBrokers(new ArrayList<String>() {
//            {
//                add("172.16.8.51:9092");
//                add("172.16.8.52:9092");
//                add("172.16.8.53:9092");
//                add("172.16.8.54:9092");
//                add("172.16.8.55:9092");
//            }
//        });
        zcb.setServers("172.16.8.51:2181,172.16.8.54:2181,172.16.8.53:2181");
        kcb.setZookeeperConfigBean(zcb);
        kcb.setRawTopic("SU-Raw");
        kcb.setEnrichedTopic("SU-Enriched");
        kcb.setCountsTopic("SU-Counts");
        kcb.setControlTopic("SU-Control");
        kcb.setViolationTopic("SU-Violations");
        LOGGER.debug("KCB populated ..");

        RedisConfigBean rcb = new RedisConfigBean();

        ArrayList<String> nodes = new ArrayList<>();
        nodes.add("172.16.8.51:6379");
        rcb.setNodes(nodes);

        rcb.setEnabled(true);
        rcb.setPassword("test123");

        HadoopConfigBean config = new HadoopConfigBean();
        config.setConfigured(true);
        config.setKafkaConfigBean(kcb);
        config.sethBaseConfigBean(hcb);
        config.setRedisConfigBean(rcb);

        IEProcessor ie = new IEProcessor(hc, config, 0);

        EnrichedEventObject eeo = new EnrichedEventObject();
        eeo.setJobid(-1L);
        eeo.setRg_id(42L);
        eeo.setAccountname("BL1227");
        eeo.setTransactionstring1("An account was successfully logged on,Logon Type=3");
        eeo.setIpaddress("172.16.37.211");
    }

    private Map<String, Tuple2<Long, Long>> addPolicyTime(Long policyId, String sigid, Long time, Map<String, Tuple2<Long, Long>> policyCountTimeInLine) {
        if (sigid == null) {
            sigid = "NA";
        }
        LOGGER.trace("Adding policy times pid:{} time:{}", policyId, time);
        if (policyCountTimeInLine.containsKey(policyId + "|" + sigid)) {
            if (policyCountTimeInLine.get(policyId + "|" + sigid)._1 == null) {
                LOGGER.trace("pid:{} sigid:{} previous time got stored as null", policyId, sigid);
            } else {
                policyCountTimeInLine.put(policyId + "|" + sigid, new Tuple2<>(policyCountTimeInLine.get(policyId + "|" + sigid)._1 + time, policyCountTimeInLine.get(policyId + "|" + sigid)._2 + 1));
            }
        } else {
            policyCountTimeInLine.put(policyId + "|" + sigid, new Tuple2<>(time, 1l));
        }

//LOGGER.info("policyCountTimeInLine:{}",policyCountTimeInLine.get(policyId + "|" + sigid));
        return policyCountTimeInLine;
    }

    private Map<String, HashMap<String, Long>> addPolicyTimebyBlock(Long policyId, String sigid, HashMap<String, Long> policyPartsTimebyEEO, Map<String, HashMap<String, Long>> policyPartsTimeInLine) {
        if (sigid == null) {
            sigid = "NA";
        }

        if (policyPartsTimeInLine.containsKey(policyId + "|" + sigid)) {
            if (policyPartsTimeInLine.get(policyId + "|" + sigid) == null) {
                LOGGER.trace("pid:{} sigid:{} previous time got stored as null", policyId, sigid);
                policyPartsTimeInLine.put(policyId + "|" + sigid, policyPartsTimebyEEO);
            } else {

                HashMap<String, Long> policyPartsTimebyEEO_BIGONE = policyPartsTimeInLine.get(policyId + "|" + sigid);
                for (String module : policyPartsTimebyEEO.keySet()) {
                    Long timeBig = policyPartsTimebyEEO_BIGONE.containsKey(module) ? policyPartsTimebyEEO_BIGONE.get(module) : 0l;
                    timeBig = timeBig + policyPartsTimebyEEO.get(module);
                    policyPartsTimebyEEO_BIGONE.put(module, timeBig);
                }
            }
        } else {
            policyPartsTimeInLine.put(policyId + "|" + sigid, policyPartsTimebyEEO);
        }
        return policyPartsTimeInLine;
    }
}
