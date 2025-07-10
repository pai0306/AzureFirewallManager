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

        // �j�w�ݩʡA�Ω�b������� WAF �����C��
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
            // �����즸���J�ɡA���汽�y
            await PerformScanAsync();
        }

        public async Task<IActionResult> OnPostScanAsync()
        {
            // ��ϥΪ��I���u���y�v���s�ɡA�A�����汽�y
            await PerformScanAsync();
            return Page(); // ��^��e����
        }

        private async Task PerformScanAsync()
        {
            try
            {
                _logger.LogInformation("���b���� WAF �������y...");
                WafPolicies = await _wafScannerService.ScanAllAccessibleWafPoliciesAsync();
                ScanErrorOccurred = false;
                _logger.LogInformation($"WAF �������y�����A��� {WafPolicies.Count} �ӵ����C");
            }
            catch (Exception ex)
            {
                _logger.LogError($"���y WAF �����ɵo�Ϳ��~: {ex.Message}");
                ScanErrorOccurred = true;
                // �z�i�H�b���B�]�m�@�ӥΤ�ͦn�����~����
            }
        }
    }
}