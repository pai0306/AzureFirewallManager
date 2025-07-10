using AzureFirewallManagerTools.Models;
using AzureFirewallManagerTools.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace AzureFirewallManagerTools.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly AzureWafScannerService _wafScannerService;

        // 綁定屬性，用於在頁面顯示 WAF 策略列表
        [BindProperty]
        public List<WafPolicyDetails> WafPolicies { get; set; } = new List<WafPolicyDetails>();

        public bool ScanErrorOccurred { get; set; } = false;

        public IndexModel(ILogger<IndexModel> logger, AzureWafScannerService wafScannerService)
        {
            _logger = logger;
            _wafScannerService = wafScannerService;
        }

        public async Task OnGetAsync()
        {
            // 當頁面初次載入時，執行掃描
            await PerformScanAsync();
        }

        public async Task<IActionResult> OnPostScanAsync()
        {
            // 當使用者點擊「掃描」按鈕時，再次執行掃描
            await PerformScanAsync();
            return Page(); // 返回當前頁面
        }

        private async Task PerformScanAsync()
        {
            try
            {
                _logger.LogInformation("正在執行 WAF 策略掃描...");
                WafPolicies = await _wafScannerService.ScanAllAccessibleWafPoliciesAsync();
                ScanErrorOccurred = false;
                _logger.LogInformation($"WAF 策略掃描完成，找到 {WafPolicies.Count} 個策略。");
            }
            catch (Exception ex)
            {
                _logger.LogError($"掃描 WAF 策略時發生錯誤: {ex.Message}");
                ScanErrorOccurred = true;
                // 您可以在此處設置一個用戶友好的錯誤消息
            }
        }
    }
}