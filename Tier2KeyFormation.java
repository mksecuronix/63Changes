/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.securonix.data.distributor;

import com.securonix.application.hibernate.tables.Configwhitelistimport;
import com.securonix.application.hibernate.tables.PolicyMaster;
import com.securonix.application.hibernate.tables.Suspectcheckslist;
import com.securonix.application.policy.PolicyConstants;
import com.securonix.application.policy.beans.RarityConfigBean;
import com.securonix.redis.RedisClient;
import com.securonix.redis.RedisNamespaceConstants;
import com.securonix.snyper.common.EnrichedEventObject;
import com.securonix.snyper.common.util.EEOUtil;
import com.securonix.snyper.config.beans.HadoopConfigBean;
import com.securonix.snyper.policy.beans.violations.Violation;
import com.securonix.snyper.policyengine.ViolationUtil;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import scala.Tuple2;

/**
 *
 * @author Securonix Inc
 */
public class Tier2KeyFormation {

    private final static Logger LOGGER = LogManager.getLogger();

    public static Map<Integer, List<EnrichedEventObject>> formKeys(List<EnrichedEventObject> tier2Violations, Integer partionCount, HadoopConfigBean hcb) {
        
        LOGGER.debug("Total Violation Events:{}", tier2Violations.size());
        
        Map<Long, Map<Long, Tuple2<PolicyMaster, RarityConfigBean>>> rarityConfigs = Tier2ConfigLoader.INSTANCE.getRarityConfigs();
        Map<Long, Map<Long, Tuple2<PolicyMaster, String>>> proxyUrlConfigs = Tier2ConfigLoader.INSTANCE.getProxyUrlConfigs();
        
        Map<Long, List<Configwhitelistimport>> whitelistsByTypeIds = Tier2ConfigLoader.INSTANCE.getWhitelistsByTypeIds();
        
        LOGGER.debug("policySummaryChecks:{}proxyUrlConfigs:{}", rarityConfigs, proxyUrlConfigs);
        
        Map<Integer, List<EnrichedEventObject>> eventsWithKey = new HashMap<>();
        Iterator<EnrichedEventObject> iterator = tier2Violations.iterator();
        Map<String, List<String>> keyToWhiteList = new HashMap<>();
        Set<String> whiteListKeysToQuery = new HashSet<>();
        
        while (iterator.hasNext()) {
            EnrichedEventObject eeo = iterator.next();
            List<Violation> violations = eeo.getTier2Violations();
            
            for (Violation violation : violations) {
                
                try {
                    Long policyId = violation.getPolicyId();
                    
                    if (rarityConfigs.containsKey(eeo.getRg_id()) && rarityConfigs.get(eeo.getRg_id()).containsKey(policyId)) { // New Rare
                        Tuple2<PolicyMaster, RarityConfigBean> summary = rarityConfigs.get(eeo.getRg_id()).get(policyId);
                        String analyticstype = summary._1().getAnalyticstype();
                        Suspectcheckslist suspectcheckslist = Tier2ConfigLoader.INSTANCE.getAllChecksById().get(summary._1.getSuspectcheckslistid().intValue());
                        List<Configwhitelistimport> whiteListIds = whitelistsByTypeIds.get(summary._1.getRiskTypeId());
                        
                        Set<String> keys = null;
                        switch (analyticstype) {
                            
                            case PolicyConstants.AT_RARITY: {
                                
                                keys = EventRarityKeyCreator.getkeys(summary, hcb, eeo);
                                
                                break;
                            }
                            
                        }
                        List<String> whiteListKeys = new ArrayList<>();
                        
                        if (whiteListIds != null && !whiteListIds.isEmpty()) {
                            Tuple2<String, String> attributesAndValue = EventRarityKeyCreator.getAttributesAndValue(suspectcheckslist, summary._2.getAttributesForClassFormation(), eeo);
                            
                            for (Configwhitelistimport configwhitelistimport : whiteListIds) {
                                String key = eeo.getTenantid() + "^~WL^~" + configwhitelistimport.getId() + "^~" + attributesAndValue._1() + "^~" + attributesAndValue._2();
                                whiteListKeys.add(key);
                                whiteListKeysToQuery.add(key);
                            }
                        }
                        
                        for (String key : keys) {
                            Integer partionId = ((Math.abs(key.hashCode())) % partionCount);
                            LOGGER.trace("key Formed:{} partition:{}Eventid:{}", key, partionId, eeo.getEventid());
                            if (!whiteListKeys.isEmpty()) {
                                keyToWhiteList.put(eeo.getEventid(), whiteListKeys);
                                
                            }
                            Violation duplicateViolation = new Violation();
                            
                            ViolationUtil.copyViolation(violation, duplicateViolation);
                            
                            duplicateViolation.setSource(key);
                            
                            EnrichedEventObject duplicate = new EnrichedEventObject();
                            EEOUtil.copyEEOValues(eeo, duplicate);
                            duplicate.setTier2Violations(new ArrayList<Violation>() {
                                {
                                    add(duplicateViolation);
                                }
                            });
                            
                            if (!eventsWithKey.containsKey(partionId)) {
                                eventsWithKey.put(partionId, new ArrayList<EnrichedEventObject>() {
                                    {
                                        add(duplicate);
                                    }
                                });
                                
                            } else {
                                eventsWithKey.get(partionId).add(duplicate);
                            }
                            
                        }
                        
                    } else if (proxyUrlConfigs.containsKey(eeo.getRg_id()) && proxyUrlConfigs.get(eeo.getRg_id()).containsKey(policyId)) {
                        
                        Tuple2<PolicyMaster, String> groupongAttr = proxyUrlConfigs.get(eeo.getRg_id()).get(policyId);
                        String attrGroup = groupongAttr._2();
                        Object enrichedEventObjectValue = EEOUtil.getEnrichedEventObjectValue(eeo, attrGroup);
                        if (enrichedEventObjectValue != null) {
                            String key = policyId + "^~" + enrichedEventObjectValue.toString();
                            Integer partionId = ((Math.abs(key.hashCode())) % partionCount);
                            LOGGER.trace("key Formed:{} partition:{}Eventid:{}", key, partionId, eeo.getEventid());
                            
                            Violation duplicateViolation = new Violation();
                            
                            ViolationUtil.copyViolation(violation, duplicateViolation);
                            
                            duplicateViolation.setSource(key);
                            
                            EnrichedEventObject duplicate = new EnrichedEventObject();
                            EEOUtil.copyEEOValues(eeo, duplicate);
                            duplicate.setTier2Violations(new ArrayList<Violation>() {
                                {
                                    add(duplicateViolation);
                                }
                            });
                            
                            if (!eventsWithKey.containsKey(partionId)) {
                                eventsWithKey.put(partionId, new ArrayList<EnrichedEventObject>() {
                                    {
                                        add(duplicate);
                                    }
                                });
                                
                            } else {
                                eventsWithKey.get(partionId).add(duplicate);
                            }
                            
                        } else {
                            LOGGER.warn("Skipping event since grouping attribute configured for policy is not present");
                        }
                        
                    } else {
                        
                        Integer partionId = -1;
                        Violation duplicateViolation = new Violation();
                        
                        ViolationUtil.copyViolation(violation, duplicateViolation);

//                    duplicateViolation.setSource(key);
                        EnrichedEventObject duplicate = new EnrichedEventObject();
                        EEOUtil.copyEEOValues(eeo, duplicate);
                        duplicate.setTier2Violations(new ArrayList<Violation>() {
                            {
                                add(duplicateViolation);
                            }
                        });
                        
                        if (!eventsWithKey.containsKey(partionId)) {
                            eventsWithKey.put(partionId, new ArrayList<EnrichedEventObject>() {
                                {
                                    add(duplicate);
                                }
                            });
                            
                        } else {
                            eventsWithKey.get(partionId).add(duplicate);
                        }
                    }
                    
                } catch (Exception ex) {
                    LOGGER.error("Error forming TIER2KEY for Violation. Skipping... {}", ex);
                }
                
            }
            
        }
        
        Map<String, String> keys = RedisClient.INSTANCE.getKeys(whiteListKeysToQuery, RedisNamespaceConstants.WHITELIST);
        LOGGER.trace("eventsWithKey Before Whitelisting:{}", eventsWithKey);
        LOGGER.trace("whiteListKeysToQuery:{}keys Retrieved:{}keyToWhiteList:{}", whiteListKeysToQuery, keys, keyToWhiteList);
        
        for (Map.Entry<Integer, List<EnrichedEventObject>> entrySet : eventsWithKey.entrySet()) {
            
              if(entrySet.getKey() == -1) {
                LOGGER.info("PartitionId:{}", entrySet.getKey());
                continue;
            }
            List<EnrichedEventObject> value = entrySet.getValue();
            Iterator<EnrichedEventObject> events = value.iterator();
            while (events.hasNext()) {
                EnrichedEventObject nextElement = events.next();
                
                LOGGER.trace("Event id:{}", nextElement.getEventid());
                
                List<String> wlKeys = keyToWhiteList.get(nextElement.getEventid());
                if (wlKeys != null) {
                    for (String wlKey : wlKeys) {
                        if (keys.containsKey(wlKey)) {
                            LOGGER.trace("Removing event from analysis as it's been whitelisted:{} event id:{}", wlKey, nextElement.getEventid());
                            events.remove();
                            break;
                        }
                        
                    }
                }
                
            }
            
        }
        
        LOGGER.trace("eventsWithKey:{}", eventsWithKey);
        return eventsWithKey;
    }

}
