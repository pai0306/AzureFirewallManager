// --- Services/AzureWafScannerService.cs ---
// 這個檔案包含與 Azure API 互動的核心邏輯，用於掃描 WAF 策略。
// 請將此檔案放在您的專案根目錄下的 'Services' 資料夾中。

using Azure.Identity; // 用於 Azure 身份驗證。
using Azure.ResourceManager; // 用於與 Azure 資源管理器互動。
using Azure.ResourceManager.FrontDoor; // 用於 Front Door WAF 策略相關的資源。
using Azure.ResourceManager.Resources; // 用於日誌記錄。
using AzureFirewallManagerTools.Models; // 引用自定義資料模型。

namespace AzureFirewallManagerTools.Services
{
    public class AzureWafScannerService
    {
        private readonly ArmClient _client; // Azure 資源管理器客戶端，用於與 Azure API 互動。
        private readonly ILogger<AzureWafScannerService> _logger; // 日誌記錄器，用於輸出日誌信息。

        // 建構函式：透過依賴注入接收日誌記錄器。
        public AzureWafScannerService(ILogger<AzureWafScannerService> logger)
        {
            var credentialOptions = new DefaultAzureCredentialOptions
            {
                AdditionallyAllowedTenants = { "*" } // 允許訪問所有可見的租用戶
            };
            _client = new ArmClient(new DefaultAzureCredential(credentialOptions));
            _logger = logger;
        }

        private ArmClient GetArmClientForSpecificTenant(string tenantId)
        {
            var credentialOptions = new DefaultAzureCredentialOptions
            {
                TenantId = tenantId // 強制憑證只從這個租用戶獲取令牌
            };
            return new ArmClient(new DefaultAzureCredential(credentialOptions));
        }


        /// <summary>
        /// 獲取當前身份有權存取的所有 Azure AD 租用戶。
        /// </summary>
        /// <returns>租用戶列表。</returns>
        public async Task<List<TenantDetails>> GetAllAccessibleTenantsAsync()
        {
            var tenants = new List<TenantDetails>();
            try
            {
                _logger.LogInformation("正在獲取所有可存取租用戶...");
                // 直接使用 _client 實例來獲取租用戶列表，因為它已經配置為可以訪問所有租用戶。
                await foreach (var tenant in _client.GetTenants())
                {
                    tenants.Add(new TenantDetails
                    {
                        Id = tenant.Data.TenantId.ToString(), // TenantId 是 Guid 類型
                        DisplayName = tenant.Data.DisplayName ?? tenant.Data.TenantId.ToString() // 如果沒有顯示名稱，則使用 ID
                    });
                }
                _logger.LogInformation($"找到 {tenants.Count} 個租用戶。");
            }
            catch (Exception ex)
            {
                _logger.LogError($"獲取租用戶列表時發生錯誤: {ex.Message}");
            }
            return tenants.OrderBy(t => t.DisplayName).ToList(); // 按顯示名稱排序
        }

        /// <summary>
        /// 獲取指定租用戶下、當前身份有權存取的所有 Azure 訂閱。
        /// </summary>
        /// <param name="tenantId">要掃描的租用戶 ID。</param>
        /// <returns>訂閱列表。</returns>
        public async Task<List<SubscriptionDetails>> GetAllAccessibleSubscriptionsAsync(string tenantId)
        {
            var subscriptions = new List<SubscriptionDetails>();
            try
            {
                _logger.LogInformation($"正在獲取租用戶 '{tenantId}' 下的所有可存取訂閱...");
                // 使用針對特定租用戶配置的 ArmClient 來獲取訂閱列表。
                // 這裡我們需要一個新的 ArmClient 實例，因為我們正在切換上下文到特定的租用戶。
                var clientForTenant = GetArmClientForSpecificTenant(tenantId);
                await foreach (var sub in clientForTenant.GetSubscriptions())
                {
                    subscriptions.Add(new SubscriptionDetails
                    {
                        Id = sub.Data.SubscriptionId,
                        DisplayName = sub.Data.DisplayName
                    });
                }
                _logger.LogInformation($"在租用戶 '{tenantId}' 下找到 {subscriptions.Count} 個訂閱。");
            }
            catch (Exception ex)
            {
                _logger.LogError($"獲取租用戶 '{tenantId}' 下的訂閱列表時發生錯誤: {ex.Message}");
            }
            return subscriptions.OrderBy(s => s.DisplayName).ToList(); // 按顯示名稱排序
        }

        /// <summary>
        /// 獲取指定訂閱中包含任何 WAF 策略資源的資源群組。
        /// </summary>
        /// <param name="tenantId">訂閱所屬的租用戶 ID。</param>
        /// <param name="subscriptionId">要掃描的訂閱 ID。</param>
        /// <returns>包含 WAF 策略的資源群組列表。</returns>
        public async Task<List<ResourceGroupDetails>> GetResourceGroupsWithWafPoliciesAsync(string tenantId, string subscriptionId)
        {
            var resourceGroupsWithWaf = new HashSet<string>(); // 使用 HashSet 避免重複
            var resultList = new List<ResourceGroupDetails>();

            try
            {
                // 使用針對特定租用戶配置的 ArmClient。
                var clientForTenant = GetArmClientForSpecificTenant(tenantId);

                // 確保 subscriptionId 被 Trim 且不為空
                string trimmedSubscriptionId = subscriptionId?.Trim();
                if (string.IsNullOrEmpty(trimmedSubscriptionId))
                {
                    _logger.LogError("GetResourceGroupsWithWafPoliciesAsync called with empty or null subscriptionId. Cannot retrieve resource groups without a valid subscription ID. Returning empty list.");
                    return resultList;
                }

                _logger.LogInformation($"嘗試獲取訂閱資源，TenantId: '{tenantId}', SubscriptionId: '{trimmedSubscriptionId}'");

                // 使用 SubscriptionResource.CreateResourceIdentifier 確保 ID 格式正確
                var subscriptionResourceId = SubscriptionResource.CreateResourceIdentifier(trimmedSubscriptionId);
                var subscription = await clientForTenant.GetSubscriptionResource(subscriptionResourceId).GetAsync();

                _logger.LogInformation($"成功獲取訂閱 '{subscription.Value.Data.DisplayName}' ({trimmedSubscriptionId})。正在掃描資源群組...");

                await foreach (var resourceGroup in subscription.Value.GetResourceGroups())
                {
                    bool hasWafPolicy = false;

                    // 只檢查 Front Door WAF Policies
                    await foreach (var fdWafPolicy in resourceGroup.GetFrontDoorWebApplicationFirewallPolicies())
                    {
                        hasWafPolicy = true;
                        break; // 找到一個就夠了，這個資源群組有 WAF 策略
                    }

                    if (hasWafPolicy)
                    {
                        if (resourceGroupsWithWaf.Add(resourceGroup.Data.Name)) // 如果是新的資源群組名稱
                        {
                            resultList.Add(new ResourceGroupDetails
                            {
                                Name = resourceGroup.Data.Name,
                                Id = resourceGroup.Data.Id
                            });
                        }
                    }
                }
                _logger.LogInformation($"在訂閱 '{subscription.Value.Data.DisplayName}' 中找到 {resultList.Count} 個包含 Front Door WAF 策略的資源群組。");
            }
            catch (Exception ex)
            {
                _logger.LogError($"獲取訂閱 '{subscriptionId}' 中包含 WAF 策略的資源群組時發生錯誤: {ex.Message}");
            }
            return resultList.OrderBy(rg => rg.Name).ToList(); // 按名稱排序
        }


        /// <summary>
        /// 掃描指定訂閱或指定資源群組中的 Front Door WAF 策略。
        /// </summary>
        /// <param name="tenantId">訂閱所屬的租用戶 ID。</param>
        /// <param name="subscriptionId">要掃描的訂閱 ID。</param>
        /// <param name="resourceGroupName">可選：要掃描的資源群組名稱。如果為 null，則掃描整個訂閱。</param>
        /// <returns>WAF 策略列表。</returns>
        public async Task<List<WafPolicyDetails>> ScanWafPoliciesAsync(string tenantId, string subscriptionId, string resourceGroupName = null)
        {
            var allWafDetails = new List<WafPolicyDetails>();

            try
            {
                // 使用針對特定租用戶配置的 ArmClient。
                var clientForTenant = GetArmClientForSpecificTenant(tenantId);

                // 確保 subscriptionId 和 resourceGroupName 被 Trim
                string currentSubscriptionId = subscriptionId?.Trim();
                string currentResourceGroupName = resourceGroupName?.Trim();

                _logger.LogInformation($"ScanWafPoliciesAsync initiated. Tenant: '{tenantId}', Subscription (param): '{subscriptionId}', Trimmed Sub: '{currentSubscriptionId}', Trimmed RG: '{currentResourceGroupName}'");

                // 如果沒有指定訂閱 ID (即選擇了「所有訂閱」)
                if (string.IsNullOrEmpty(currentSubscriptionId))
                {
                    _logger.LogInformation($"Scanning all subscriptions for tenant '{tenantId}'.");
                    await foreach (var sub in clientForTenant.GetSubscriptions())
                    {
                        var currentSubName = sub.Data.DisplayName;
                        var currentSubId = sub.Data.SubscriptionId;
                        _logger.LogInformation($"  Processing subscription: {currentSubName} ({currentSubId})");

                        // 如果指定了資源群組，則需要在該訂閱內進行篩選
                        if (!string.IsNullOrEmpty(currentResourceGroupName))
                        {
                            _logger.LogInformation($"    Filtering by resource group '{currentResourceGroupName}' within subscription '{currentSubId}'.");
                            var rg = await sub.GetResourceGroupAsync(currentResourceGroupName);
                            if (rg.HasValue)
                            {
                                await ScanResourceGroupForFrontDoorWafPolicies(rg.Value, currentSubName, currentSubId, allWafDetails);
                            }
                            else
                            {
                                _logger.LogWarning($"    Resource group '{currentResourceGroupName}' not found in subscription '{currentSubId}'.");
                            }
                        }
                        else // 沒有指定資源群組，掃描該訂閱下所有資源群組
                        {
                            await foreach (var rg in sub.GetResourceGroups())
                            {
                                await ScanResourceGroupForFrontDoorWafPolicies(rg, currentSubName, currentSubId, allWafDetails);
                            }
                        }
                    }
                }
                else // 指定了單個訂閱 ID
                {
                    _logger.LogInformation($"Scanning specific subscription '{currentSubscriptionId}' for tenant '{tenantId}'.");

                    // 再次防禦性檢查，確保訂閱 ID 在這裡不會是空的
                    if (string.IsNullOrEmpty(currentSubscriptionId))
                    {
                        _logger.LogError($"CRITICAL ERROR: currentSubscriptionId is unexpectedly empty in the single subscription scan path for tenant '{tenantId}'. This indicates a logical flow issue or data corruption.");
                        return allWafDetails;
                    }

                    // 使用 SubscriptionResource.CreateResourceIdentifier 確保 ID 格式正確
                    var subscriptionResourceId = SubscriptionResource.CreateResourceIdentifier(currentSubscriptionId);
                    var subscriptionResource = await clientForTenant.GetSubscriptionResource(subscriptionResourceId).GetAsync();
                    var subscriptionName = subscriptionResource.Value.Data.DisplayName;

                    if (string.IsNullOrEmpty(currentResourceGroupName))
                    {
                        _logger.LogInformation($"Scanning all resource groups in subscription '{subscriptionName}' ({currentSubscriptionId}).");
                        await foreach (var rg in subscriptionResource.Value.GetResourceGroups())
                        {
                            await ScanResourceGroupForFrontDoorWafPolicies(rg, subscriptionName, currentSubscriptionId, allWafDetails);
                        }
                    }
                    else
                    {
                        _logger.LogInformation($"Scanning specific resource group '{currentResourceGroupName}' in subscription '{subscriptionName}' ({currentSubscriptionId}).");
                        var resourceGroup = await subscriptionResource.Value.GetResourceGroupAsync(currentResourceGroupName);
                        if (resourceGroup.HasValue)
                        {
                            await ScanResourceGroupForFrontDoorWafPolicies(resourceGroup.Value, subscriptionName, currentSubscriptionId, allWafDetails);
                        }
                        else
                        {
                            _logger.LogWarning($"Resource group '{currentResourceGroupName}' not found in subscription '{currentSubscriptionId}'.");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"掃描 Front Door WAF 策略時發生致命錯誤: {ex.Message}");
            }
            return allWafDetails;
        }

        // 輔助方法：掃描單個資源群組中的 Front Door WAF 策略
        private async Task ScanResourceGroupForFrontDoorWafPolicies(
            ResourceGroupResource resourceGroup,
            string subscriptionName,
            string subscriptionId,
            List<WafPolicyDetails> allWafDetails)
        {
            var resourceGroupName = resourceGroup.Data.Name;
            _logger.LogInformation($"  正在掃描資源群組: {resourceGroupName}...");

            // --- 只掃描 Front Door WAF 策略資源 ---
            await foreach (var fdPolicy in resourceGroup.GetFrontDoorWebApplicationFirewallPolicies())
            {
                try
                {
                    _logger.LogInformation($"    正在取得 Front Door WAF 策略: {fdPolicy.Data.Name}");
                    allWafDetails.Add(MapFrontDoorWafPolicy(fdPolicy.Data, subscriptionName, subscriptionId, resourceGroupName));
                }
                catch (Exception ex)
                {
                    _logger.LogWarning($"警告: 無法取得 Front Door WAF 策略 '{fdPolicy.Data.Name}' (訂閱: {subscriptionName}, 資源群組: {resourceGroupName})。錯誤: {ex.Message}");
                }
            }
        }

        // MapFrontDoorWafPolicy 方法：將 Front Door WAF 策略數據映射到 WafPolicyDetails。
        private WafPolicyDetails MapFrontDoorWafPolicy(FrontDoorWebApplicationFirewallPolicyData policy, string subscriptionName, string subscriptionId, string resourceGroupName)
        {
            var details = new WafPolicyDetails
            {
                Name = policy.Name,
                Type = "Front Door WAF Policy", // 類型固定為 Front Door WAF Policy
                AssociatedResource = "N/A (Linked to Front Door instance)", // Front Door WAF 策略是全域的，然後鏈接到 Front Door 實例。
                SubscriptionName = subscriptionName,
                SubscriptionId = subscriptionId,
                ResourceGroupName = resourceGroupName
            };

            // Managed Rules
            if (policy.ManagedRuleSets != null)
            {
                foreach (var ruleSet in policy.ManagedRuleSets)
                {
                    var managedRuleSetDetails = new ManagedRuleSetDetails
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
                            DisabledRules = groupOverride.Rules?.Where(r => r.EnabledState.Equals(Azure.ResourceManager.FrontDoor.Models.ManagedRuleEnabledState.Disabled)).Select(r => r.RuleId).ToList() ?? new List<string>(),
                            // 新增：映射 ManagedRuleOverride 列表
                            Rules = groupOverride.Rules?.Select(r => new ManagedRuleOverrideDetails
                            {
                                RuleId = r.RuleId,
                                State = r.EnabledState.ToString(),
                                ExclustionCount = r.Exclusions?.Count ?? 0, // 新增：計算排除項數量
                                Exclusions = r.Exclusions?.Select(e =>
                                {
                                    var exclusionDetails = new ExclusionDetails
                                    {
                                        MatchVariable = e.MatchVariable.ToString(),
                                        SelectorMatchOperator = e.SelectorMatchOperator.ToString(),
                                        Selector = e.Selector
                                    };

                                    return exclusionDetails;
                                }).ToList() ?? new List<ExclusionDetails>()
                            }).ToList() ?? new List<ManagedRuleOverrideDetails>()
                        };
                        managedRuleSetDetails.RuleGroupOverrides.Add(groupDetails);
                    }
                    details.ManagedRules.Add(managedRuleSetDetails);
                }
            }

            // Custom Rules
            if (policy.Rules != null)
            {
                details.CustomRules = policy.Rules.Select(cr => new CustomRuleDetails
                {
                    Name = cr.Name,
                    Priority = cr.Priority,
                    Action = cr.Action.ToString(),
                    RuleType = cr.RuleType.ToString(),
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
