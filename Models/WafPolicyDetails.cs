using Azure.ResourceManager.FrontDoor.Models;
using System.Collections.Generic;

namespace AzureFirewallManagerTools.Models
{
    // WAFPolicyDetails 類別：表示一個 Azure WAF 策略的詳細資訊。
    public class WafPolicyDetails
    {
        public string Name { get; set; } // WAF 策略的名稱。
        public string Type { get; set; } // WAF 策略的類型 (例如："Application Gateway WAF Policy", "Front Door WAF Policy")。
        public string AssociatedResource { get; set; } // WAF 策略關聯的資源名稱 (例如：關聯的 Application Gateway 名稱)。
                                                       // 對於 Front Door WAF 策略，可能為 "N/A (Linked to Front Door instance)"，因為它們是全域的。
        public string SubscriptionName { get; set; } // WAF 策略所屬訂閱的顯示名稱。
        public string SubscriptionId { get; set; } // WAF 策略所屬訂閱的 ID。
        public string ResourceGroupName { get; set; } // WAF 策略所屬資源群組的名稱。

        // 託管規則集列表。
        public List<ManagedRuleSetDetails> ManagedRules { get; set; } = new List<ManagedRuleSetDetails>();
        // 自訂規則列表。
        public List<CustomRuleDetails> CustomRules { get; set; } = new List<CustomRuleDetails>();
        // 排除項列表 (主要用於 Front Door WAF 策略)。
        public List<ExclusionDetails> Exclusions { get; set; } = new List<ExclusionDetails>();
    }

    // ManagedRuleSetDetails 類別：表示一個託管規則集。
    public class ManagedRuleSetDetails
    {
        public string RuleSetType { get; set; } // 規則集類型 (例如："OWASP")。
        public string RuleSetVersion { get; set; } // 規則集版本 (例如："3.1")。
        // 規則群組覆寫列表，用於指定託管規則集中哪些規則被禁用。
        public List<RuleGroupOverrideDetails> RuleGroupOverrides { get; set; } = new List<RuleGroupOverrideDetails>();
    }

    // RuleGroupOverrideDetails 類別：表示託管規則集中一個規則群組的覆寫。
    public class RuleGroupOverrideDetails
    {
        public string RuleGroupName { get; set; } // 規則群組名稱 (例如："SQLInjection")。
        // 被禁用的規則 ID 列表。
        public List<string> DisabledRules { get; set; } = new List<string>();
        // 明確列出被覆寫的規則 (ManagedRuleOverride)。
        public List<ManagedRuleOverrideDetails> Rules { get; set; } = new List<ManagedRuleOverrideDetails>();
    }

    // ManagedRuleOverrideDetails 類別，表示被覆寫的單個託管規則。
    public class ManagedRuleOverrideDetails
    {
        public string RuleId { get; set; }
        public string State { get; set; } // 例如："Enabled", "Disabled"
        // 注意：ManagedRuleOverride 在 SDK 中沒有直接的 Action 屬性。
        // Action 通常在規則集或策略層級定義。
        public int ExclustionCount { get; set; }
        // 新增：針對此規則群組的排除項列表。
        public List<ExclusionDetails> Exclusions { get; set; } = new List<ExclusionDetails>();
    }

    // CustomRuleDetails 類別：表示一個自訂規則。
    public class CustomRuleDetails
    {
        public string Name { get; set; } // 自訂規則的名稱。
        public int Priority { get; set; } // 規則的優先順序。
        public string Action { get; set; } // 規則匹配時採取的動作 (例如："Allow", "Block", "Log", "Redirect")。
        public string RuleType { get; set; } // 規則類型 (例如："MatchRule", "RateLimitRule")。
        // 匹配條件列表。
        public List<MatchConditionDetails> MatchConditions { get; set; } = new List<MatchConditionDetails>();
    }

    // MatchConditionDetails 類別：表示一個匹配條件。
    public class MatchConditionDetails
    {
        public string MatchVariable { get; set; } // 匹配變數 (例如："RemoteAddr", "RequestHeaders")。
        public string Operator { get; set; } // 匹配運算子 (例如："IPMatch", "Contains")。
        public List<string> MatchValues { get; set; } = new List<string>(); // 匹配值列表。
        public string Selector { get; set; } // 選擇器 (例如：對於 RequestHeaders，可以是 "User-Agent")。
        public List<string> Transforms { get; set; } = new List<string>(); // 轉換列表 (例如："Lowercase", "Trim")。
    }

    // ExclusionDetails 類別：表示一個排除項。
    // 已擴展以包含針對託管規則集、規則群組和特定規則的排除目標。
    public class ExclusionDetails
    {
        public string MatchVariable { get; set; } // 匹配變數 (例如："RequestHeaderNames", "RequestBodyPostArgNames")。
        public string SelectorMatchOperator { get; set; } // 選擇器匹配運算子 (例如："Equals", "StartsWith")。
        public string Selector { get; set; } // 選擇器 (例如："CookieName", "ParamName")。

        // 針對託管規則集的排除。
        public List<ManagedRuleSetExclusionDetails> ManagedRuleSetExclusions { get; set; } = new List<ManagedRuleSetExclusionDetails>();
        // 針對規則群組的排除。
        public List<RuleGroupExclusionDetails> RuleGroupExclusions { get; set; } = new List<RuleGroupExclusionDetails>();
        // 針對特定規則的排除。
        public List<RuleExclusionDetails> RuleExclusions { get; set; } = new List<RuleExclusionDetails>();
    }

    // ManagedRuleSetExclusionDetails 類別：表示針對託管規則集的排除。
    public class ManagedRuleSetExclusionDetails
    {
        public string RuleSetType { get; set; }
        public string RuleSetVersion { get; set; }
        public List<RuleGroupExclusionDetails> RuleGroupExclusions { get; set; } = new List<RuleGroupExclusionDetails>();
    }

    // RuleGroupExclusionDetails 類別：表示針對規則群組的排除。
    public class RuleGroupExclusionDetails
    {
        public string RuleGroupName { get; set; }
        public List<RuleExclusionDetails> Rules { get; set; } = new List<RuleExclusionDetails>();
    }

    // RuleExclusionDetails 類別：表示針對特定規則的排除。
    public class RuleExclusionDetails
    {
        public string RuleId { get; set; }
    }
}