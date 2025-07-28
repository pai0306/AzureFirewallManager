// Models/WafNoteEntity.cs
using Azure; // 引入 ETag
using Azure.Data.Tables;
using System;

public class WafNoteEntity : ITableEntity
{
    // --- ITableEntity 介面要求的核心屬性 ---
    public string PartitionKey { get; set; } // 分區鍵，用於分組
    public string RowKey { get; set; }     // 列鍵，在 PartitionKey 內唯一識別實體
    public DateTimeOffset? Timestamp { get; set; } // 時間戳記，服務自動管理
    public ETag ETag { get; set; }         // 版本標識符，服務自動管理

    // --- 備註的內容屬性 ---
    public string NotesContent { get; set; } // 實際的備註文字

    // --- 備註的類型 (用於後端判斷如何解析鍵值和日後擴展) ---
    public string EntityType { get; set; } // 例如: "WafPolicy", "CustomRule", "ManagedRuleOverride", "MatchValue"

    // --- 為了方便在 Table Storage 中查詢和閱讀，可儲存原始的上下文識別資訊 ---
    // (這些屬性不構成 PartitionKey 和 RowKey，但對理解資料很有用)
    public string SubscriptionId { get; set; }
    public string ResourceGroupName { get; set; }
    public string WafPolicyName { get; set; }
    public string CustomRuleName { get; set; }
    public int? MatchConditionIndex { get; set; } // 針對 MatchValue 備註
    public string MatchValue { get; set; } // 針對 MatchValue 備註 (原始 IP 或其他值)
    public string ManagedRuleSetType { get; set; } // 針對 ManagedRuleOverride 備註
    public string ManagedRuleSetVersion { get; set; } // 針對 ManagedRuleOverride 備註
    public string RuleGroupName { get; set; } // 針對 ManagedRuleOverride 備註
    public string RuleId { get; set; } // 針對 ManagedRuleOverride 備註
}