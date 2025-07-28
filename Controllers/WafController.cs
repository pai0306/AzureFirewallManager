using AzureFirewallManagerTools.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;
using System.Web;

namespace AzureFirewallManagerTools.Controllers
{
    [ApiController]
    [Route("api/wafnotes")]
    public class WafNotesController : ControllerBase
    {
        private readonly AzureWafService _wafService;
        private readonly ILogger<WafNotesController> _logger;

        public WafNotesController(AzureWafService wafService, ILogger<WafNotesController> logger)
        {
            _wafService = wafService;
            _logger = logger;
        }

        [HttpPost("save")]
        public async Task<IActionResult> SaveNote([FromBody] NoteSaveRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // 根據 EntityType 組裝 PartitionKey 和 RowKey
            string partitionKey = "";
            string rowKey = "";

            try
            {
                switch (request.EntityType)
                {
                    case "WafPolicy":
                        partitionKey = request.WafPolicyName;
                        rowKey = request.WafPolicyName; // 可以是策略名稱或 "PolicyNotes"
                        break;
                    case "CustomRule":
                        partitionKey = $"{request.WafPolicyName}_{request.CustomRuleName}";
                        rowKey = request.CustomRuleName; // 可以是規則名稱或 "RuleNotes"
                        break;
                    case "ManagedRuleOverride":
                        partitionKey = $"{request.WafPolicyName}_{request.ManagedRuleSetType}_{request.ManagedRuleSetVersion}_{request.RuleGroupName}";
                        rowKey = Uri.EscapeDataString(request.RuleId); // 確保這裡也進行了 URL 編碼
                        break;
                    case "MatchValue":
                        // 將 PolicyName_CustomRuleName 作為 PartitionKey
                        partitionKey = $"{request.WafPolicyName}_{request.CustomRuleName}";
                        // 將 MatchConditionIndex 和編碼後的 MatchValue 作為 RowKey
                        rowKey = $"MC_{request.MatchConditionIndex}_{HttpUtility.UrlEncode(request.MatchValue)}";
                        break;
                    default:
                        return BadRequest("無效的實體類型。");
                }

                var wafNoteEntity = new WafNoteEntity
                {
                    PartitionKey = partitionKey,
                    RowKey = rowKey,
                    NotesContent = request.NotesContent,
                    EntityType = request.EntityType,
                    // 填充原始上下文資訊以便查詢和理解 (可選但推薦)
                    SubscriptionId = request.SubscriptionId, // 這些需要從前端或服務中獲取
                    ResourceGroupName = request.ResourceGroupName,
                    WafPolicyName = request.WafPolicyName,
                    CustomRuleName = request.CustomRuleName,
                    MatchConditionIndex = request.MatchConditionIndex,
                    MatchValue = request.MatchValue,
                    ManagedRuleSetType = request.ManagedRuleSetType,
                    ManagedRuleSetVersion = request.ManagedRuleSetVersion,
                    RuleGroupName = request.RuleGroupName,
                    RuleId = request.RuleId
                };

                bool success = await _wafService.SaveNotesAsync(wafNoteEntity);

                if (success)
                {
                    return Ok(new { message = "備註已成功保存。", newNotesContent = request.NotesContent });
                }
                else
                {
                    return StatusCode(500, new { message = "保存備註失敗，請檢查日誌。" });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"保存備註時發生未預期錯誤: {ex.Message}");
                return StatusCode(500, new { message = $"內部伺服器錯誤: {ex.Message}" });
            }
        }
    }

    // 用於接收前端請求的資料模型
    public class NoteSaveRequest
    {
        [JsonPropertyName("notesContent")]
        public string NotesContent { get; set; } = string.Empty;
        [JsonPropertyName("entityType")]
        public string EntityType { get; set; } = string.Empty;

        // 這些屬性會根據 EntityType 有選擇性地填充
        [JsonPropertyName("wafPolicyName")]
        public string WafPolicyName { get; set; } = string.Empty;
        [JsonPropertyName("customRuleName")]
        public string CustomRuleName { get; set; } = string.Empty;
        [JsonPropertyName("matchConditionIndex")]
        public int? MatchConditionIndex { get; set; }
        [JsonPropertyName("matchValue")]
        public string MatchValue { get; set; } = string.Empty; // 原始的 IP 或匹配值
        [JsonPropertyName("managedRuleSetType")]
        public string ManagedRuleSetType { get; set; } = string.Empty;
        [JsonPropertyName("managedRuleSetVersion")]
        public string ManagedRuleSetVersion { get; set; } = string.Empty;
        [JsonPropertyName("ruleGroupName")]
        public string RuleGroupName { get; set; } = string.Empty;
        [JsonPropertyName("ruleId")]
        public string RuleId { get; set; } = string.Empty;

        // 您可能還需要傳遞訂閱和資源組 ID 來完善備註的上下文
        [JsonPropertyName("subscriptionId")]
        public string SubscriptionId { get; set; } = string.Empty;
        [JsonPropertyName("resourceGroupName")]
        public string ResourceGroupName { get; set; } = string.Empty;
    }
}
