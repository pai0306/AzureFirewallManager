// --- Services/AzureWafScannerService.cs ---
// 這個檔案包含與 Azure API 互動的核心邏輯，用於掃描 WAF 策略。
// 請將此檔案放在您的專案根目錄下的 'Services' 資料夾中。

using Azure.Identity; // 用於 Azure 身份驗證。
using Azure.ResourceManager; // 用於與 Azure 資源管理器互動。
using Azure.ResourceManager.Network; // 用於 Application Gateway WAF 策略相關的資源。
using Azure.ResourceManager.Network.Models; // 用於 Application Gateway WAF 策略特定的模型。
using Azure.ResourceManager.FrontDoor; // 用於 Front Door WAF 策略相關的資源。
using Azure.ResourceManager.FrontDoor.Models; // 用於 Front Door WAF 策略特定的模型。
using AzureFirewallManagerTools.Models; // 引用自定義資料模型。
using System.Collections.Generic;
using System.Threading.Tasks;
using System;
using System.Linq;
using Microsoft.Extensions.Logging; // 用於日誌記錄。

namespace AzureFirewallManagerTools.Services
{
    public class AzureWafScannerService
    {
        private readonly ArmClient _client; // Azure 資源管理器客戶端，用於與 Azure API 互動。
        private readonly ILogger<AzureWafScannerService> _logger; // 日誌記錄器，用於輸出日誌信息。

        // 建構函式：透過依賴注入接收日誌記錄器。
        public AzureWafScannerService(ILogger<AzureWafScannerService> logger)
        {
            // DefaultAzureCredential 會自動嘗試多種驗證方式，
            // 在 Azure App Service 環境中，它會自動使用 App Service 的受控識別進行身份驗證。
            _client = new ArmClient(new DefaultAzureCredential());
            _logger = logger;
        }

        // ScanAllAccessibleWafPoliciesAsync 方法：掃描所有可存取訂閱中的 WAF 策略。
        public async Task<List<WafPolicyDetails>> ScanAllAccessibleWafPoliciesAsync()
        {
            var allWafDetails = new List<WafPolicyDetails>(); // 用於儲存所有掃描到的 WAF 策略詳細資訊。

            try
            {
                _logger.LogInformation("正在獲取所有可存取訂閱...");
                // 遍歷當前身份有權存取的所有 Azure 訂閱。
                await foreach (var subscription in _client.GetSubscriptions())
                {
                    var subscriptionName = subscription.Data.DisplayName;
                    var subscriptionId = subscription.Data.SubscriptionId;
                    _logger.LogInformation($"正在掃描訂閱: {subscriptionName} ({subscriptionId})");

                    // 遍歷該訂閱下的所有資源群組。
                    await foreach (var resourceGroup in subscription.GetResourceGroups())
                    {
                        var resourceGroupName = resourceGroup.Data.Name;
                        _logger.LogInformation($"  正在掃描資源群組: {resourceGroupName}...");

                        // --- 掃描 Application Gateway WAF 策略 ---
                        await foreach (var appGateway in resourceGroup.GetApplicationGateways())
                        {
                            // 更正：檢查 Application Gateway 是否直接關聯了頂層 WAF 策略。
                            // 使用 appGateway.Data.FirewallPolicy?.Id 來獲取策略 ID。
                            if (appGateway.Data.FirewallPolicyId != null)
                            {
                                var policyResourceId = new Azure.Core.ResourceIdentifier(appGateway.Data.FirewallPolicyId);
                                try
                                {
                                    _logger.LogInformation($"    正在取得 Application Gateway '{appGateway.Data.Name}' 關聯的 WAF 策略: {policyResourceId.Name}");
                                    // 獲取 WAF 策略的詳細資訊。
                                    var wafPolicy = await _client.GetWebApplicationFirewallPolicyResource(policyResourceId).GetAsync();
                                    // 將獲取的策略數據映射到自定義模型並添加到列表中。
                                    allWafDetails.Add(MapAppGatewayWafPolicy(wafPolicy.Value, appGateway.Data.Name, subscriptionName, subscriptionId, resourceGroupName));
                                }
                                catch (Exception ex)
                                {
                                    // 記錄無法獲取策略的警告，例如由於權限不足。
                                    _logger.LogWarning($"警告: 無法取得 App Gateway '{appGateway.Data.Name}' (訂閱: {subscriptionName}, 資源群組: {resourceGroupName}) 關聯的 WAF 策略 {policyResourceId.Name}。錯誤: {ex.Message}");
                                }
                            }
                            // 如果 App Gateway 使用的是舊版內聯 WAF 配置 (非頂層 WAF Policy)，則此處不會被掃描到。
                            // 現代的 WAF 部署通常都建議使用頂層 WAF Policy。
                        }

                        // --- 掃描 Front Door WAF 策略 ---
                        await foreach (var fdPolicy in resourceGroup.GetFrontDoorWebApplicationFirewallPolicies())
                        {
                            try
                            {
                                _logger.LogInformation($"    正在取得 Front Door WAF 策略: {fdPolicy.Data.Name}");
                                // 將獲取的策略數據映射到自定義模型並添加到列表中。
                                allWafDetails.Add(MapFrontDoorWafPolicy(fdPolicy.Data, subscriptionName, subscriptionId, resourceGroupName));
                            }
                            catch (Exception ex)
                            {
                                // 記錄無法獲取策略的警告。
                                _logger.LogWarning($"警告: 無法取得 Front Door WAF 策略 '{fdPolicy.Data.Name}' (訂閱: {subscriptionName}, 資源群組: {resourceGroupName})。錯誤: {ex.Message}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // 記錄掃描過程中發生的致命錯誤。
                _logger.LogError($"掃描 Azure WAF 策略時發生致命錯誤: {ex.Message}");
            }
            return allWafDetails; // 返回所有掃描到的 WAF 策略詳細資訊。
        }

        // --- 輔助映射方法 ---
        // 這些方法將 Azure SDK 返回的複雜物件映射到我們更簡單的自定義資料模型。

        // MapAppGatewayWafPolicy 方法：將 Application Gateway WAF 策略數據映射到 WafPolicyDetails。
        private WafPolicyDetails MapAppGatewayWafPolicy(WebApplicationFirewallPolicyResource policy, string associatedGatewayName, string subscriptionName, string subscriptionId, string resourceGroupName)
        {
            var details = new WafPolicyDetails
            {
                Name = policy.Data.Name,
                Type = "Application Gateway WAF Policy",
                AssociatedResource = associatedGatewayName,
                SubscriptionName = subscriptionName,
                SubscriptionId = subscriptionId,
                ResourceGroupName = resourceGroupName
            };

            // 映射託管規則。
            if (policy.Data.ManagedRules != null)
            {
                foreach (var ruleSet in policy.Data.ManagedRules.ManagedRuleSets)
                {
                    var managedRuleSetDetails = new AGManagedRuleSetDetails
                    {
                        RuleSetType = ruleSet.RuleSetType,
                        RuleSetVersion = ruleSet.RuleSetVersion,
                        RuleGroupOverrides = new List<RuleGroupOverrideDetails>()
                    };

                    foreach (var groupOverride in ruleSet.RuleGroupOverrides)
                    {
                        var groupDetails = new RuleGroupOverrideDetails
                        {
                            RuleGroupName = groupOverride.RuleGroupName,
                            // 獲取被禁用的規則 ID。
                            DisabledRules = groupOverride.Rules?.Where(r => r.State == Azure.ResourceManager.Network.Models.ManagedRuleEnabledState.Disabled).Select(r => r.RuleId).ToList() ?? new List<string>()
                        };
                        managedRuleSetDetails.RuleGroupOverrides.Add(groupDetails);
                    }
                    details.AGManagedRules.Add(managedRuleSetDetails);
                }
            }

            // 映射自訂規則。
            if (policy.Data.CustomRules != null)
            {
                details.CustomRules = policy.Data.CustomRules.Select(cr => new CustomRuleDetails
                {
                    Name = cr.Name,
                    Priority = cr.Priority,
                    Action = cr.Action.ToString(),
                    RuleType = cr.RuleType.ToString(),
                    // 映射匹配條件。
                    MatchConditions = cr.MatchConditions?.Select(mc => new MatchConditionDetails
                    {
                        MatchVariable = mc.MatchVariables.FirstOrDefault()?.VariableName.ToString(), // 假設只有一個匹配變數
                        Operator = mc.Operator.ToString(),
                        MatchValues = mc.MatchValues?.ToList() ?? new List<string>(),
                        Selector = mc.MatchVariables.FirstOrDefault()?.Selector,
                        Transforms = mc.Transforms?.Select(t => t.ToString()).ToList() ?? new List<string>()
                    }).ToList() ?? new List<MatchConditionDetails>()
                }).ToList();
            }

            // App Gateway 的排除項解析可能更複雜，取決於其配置方式。
            // 此範例暫不包含詳細的 App Gateway 排除項解析。
            // 如果需要，您可以根據 policy.Data.ManagedRules.Exclusions 或其他相關屬性進行擴展。

            return details;
        }

        // MapFrontDoorWafPolicy 方法：將 Front Door WAF 策略數據映射到 WafPolicyDetails。
        private WafPolicyDetails MapFrontDoorWafPolicy(FrontDoorWebApplicationFirewallPolicyData policy, string subscriptionName, string subscriptionId, string resourceGroupName)
        {
            var details = new WafPolicyDetails
            {
                Name = policy.Name,
                Type = "Front Door WAF Policy",
                AssociatedResource = "N/A (Linked to Front Door instance)", // Front Door WAF 策略是全域的，然後鏈接到 Front Door 實例。
                SubscriptionName = subscriptionName,
                SubscriptionId = subscriptionId,
                ResourceGroupName = resourceGroupName
            };

            // 映射託管規則。
            if (policy.ManagedRuleSets != null)
            {
                foreach (var ruleSet in policy.ManagedRuleSets)
                {
                    var managedRuleSetDetails = new FDManagedRuleSetDetails
                    {
                        RuleSetType = ruleSet.RuleSetType,
                        RuleSetVersion = ruleSet.RuleSetVersion,
                        RuleGroupOverrides = new List<ManagedRulesExclusions>()
                    };

                    foreach (var groupOverride in ruleSet.RuleGroupOverrides)
                    {
                        var groupDetails = new ManagedRulesExclusions
                        {
                            RuleGroupName = groupOverride.RuleGroupName,
                            RuleCount = groupOverride.Rules?.Count ?? 0
                        };
                        managedRuleSetDetails.RuleGroupOverrides.Add(groupDetails);
                    }
                    details.FDManagedRules.Add(managedRuleSetDetails);

                    foreach (var exclusion in ruleSet.Exclusions)
                    {
                        // Front Door 的排除項通常在 ManagedRuleSets 中。
                        details.Exclusions.Add(new ExclusionDetails
                        {
                            MatchVariable = exclusion.MatchVariable.ToString(),
                            SelectorMatchOperator = exclusion.SelectorMatchOperator.ToString(),
                            Selector = exclusion.Selector
                        });
                    }
                }
            }

            // 映射自訂規則。
            if (policy.Rules != null)
            {
                details.CustomRules = policy.Rules.Select(cr => new CustomRuleDetails
                {
                    Name = cr.Name,
                    Priority = cr.Priority,
                    Action = cr.Action.ToString(),
                    RuleType = cr.RuleType.ToString() ?? "MatchRule", // Front Door 有 RateLimitRuleType
                    // 映射匹配條件。
                    MatchConditions = cr.MatchConditions?.Select(mc => new MatchConditionDetails
                    {
                        MatchVariable = mc.MatchVariable.ToString(),
                        Operator = mc.Operator.ToString(),
                        MatchValues = mc.MatchValue?.ToList() ?? new List<string>(),
                        Selector = mc.Selector,
                        Transforms = mc.Transforms?.Select(t => t.ToString()).ToList() ?? new List<string>()
                    }).ToList() ?? new List<MatchConditionDetails>()
                }).ToList();
            }

            return details;
        }
    }
}
