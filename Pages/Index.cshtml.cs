using AzureFirewallManagerTools.Models;
using AzureFirewallManagerTools.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace AzureFirewallManagerTools.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger; // ��x�O�����C
        private readonly AzureWafScannerService _wafScannerService; // WAF ���y�A�Ȫ���ҡC

        // �j�w�ݩʡA�Ω�b������� WAF �����C��C
        [BindProperty]
        public List<WafPolicyDetails> WafPolicies { get; set; } = new List<WafPolicyDetails>();

        // �j�w�ݩʡA�Ω�U�Կ�椤��w�����Τ� ID�C
        [BindProperty]
        public string SelectedTenantId { get; set; }

        // �j�w�ݩʡA�Ω�U�Կ�椤��w���q�\ ID�C
        [BindProperty]
        public string SelectedSubscriptionId { get; set; }

        // �j�w�ݩʡA�Ω�U�Կ�椤��w���귽�s�զW�١C
        [BindProperty]
        public string SelectedResourceGroupName { get; set; }

        // �i�Ϊ����Τ�C��A�Ω�U�Կ��C
        public List<SelectListItem> AvailableTenants { get; set; } = new List<SelectListItem>();

        // �i�Ϊ��q�\�C��A�Ω�U�Կ��C
        public List<SelectListItem> AvailableSubscriptions { get; set; } = new List<SelectListItem>();

        // �i�Ϊ��귽�s�զC��A�Ω�U�Կ��C
        public List<SelectListItem> AvailableResourceGroups { get; set; } = new List<SelectListItem>();

        // �аO���y�O�_�o�Ϳ��~�A�Ω�b UI �W��ܿ��~�T���C
        public bool ScanErrorOccurred { get; set; } = false;

        // �аO�O�_�w��ܯ��Τ�C
        public bool IsTenantSelected => !string.IsNullOrEmpty(SelectedTenantId);

        // �аO�O�_�w��ܭq�\�C
        public bool IsSubscriptionSelected => !string.IsNullOrEmpty(SelectedSubscriptionId);

        // �аO�O�_�w��ܸ귽�s�աC
        public bool IsResourceGroupSelected => !string.IsNullOrEmpty(SelectedResourceGroupName);

        // �غc�禡�G�z�L�̿�`�J������x�O�����M WAF ���y�A�ȡC
        public IndexModel(ILogger<IndexModel> logger, AzureWafScannerService wafScannerService)
        {
            _logger = logger;
            _wafScannerService = wafScannerService;
        }

        // OnGetAsync ��k�G�����즸���J�ɰ���C
        public async Task OnGetAsync()
        {
            await LoadTenantsAsync(); // �������J�Ҧ��i�Ϊ����Τ�C

            // �b�����q�A������ WAF �������y�A�u�ǳƤU�Կ��C
            if (IsTenantSelected)
            {
                await LoadSubscriptionsAsync(SelectedTenantId);
                if (IsSubscriptionSelected)
                {
                    await LoadResourceGroupsAsync(SelectedTenantId, SelectedSubscriptionId);
                    // �p�G���w�諸���Τ�M�q�\�A�h�b OnGet �ɰ���@�����y
                    // �o�˷�Τ᪽���X�ݱa���Ѽƪ� URL �ɡA�]����ܼƾڡC
                    await PerformScanAsync(SelectedTenantId, SelectedSubscriptionId, SelectedResourceGroupName);
                }
            }
        }

        // OnPostSelectTenantAsync ��k�G�B�z���Τ��ܨƥ�C
        public async Task<IActionResult> OnPostSelectTenantAsync()
        {
            await LoadTenantsAsync(); // ���s���J���Τ�C��C
            AvailableSubscriptions.Clear(); // �M�ŭq�\�C��C
            AvailableResourceGroups.Clear(); // �M�Ÿ귽�s�զC��C
            WafPolicies.Clear(); // �M�� WAF �����C��C
            ScanErrorOccurred = false;
            SelectedSubscriptionId = ""; // ���m�q�\��ܡC
            SelectedResourceGroupName = ""; // ���m�귽�s�տ�ܡC

            if (IsTenantSelected)
            {
                await LoadSubscriptionsAsync(SelectedTenantId); // ���J�ҿﯲ�Τ�U���q�\�C
                // ��ܯ��Τ��A���ߧY���y WAF�A���ݭq�\��ܡC
            }
            return Page(); // ��^��e�����C
        }

        // OnPostSelectSubscriptionAsync ��k�G�B�z�q�\��ܨƥ�C
        public async Task<IActionResult> OnPostSelectSubscriptionAsync()
        {
            await LoadTenantsAsync(); // ���s���J���Τ�C��C
            if (IsTenantSelected)
            {
                await LoadSubscriptionsAsync(SelectedTenantId); // ���s���J�q�\�C��C
                AvailableResourceGroups.Clear(); // �M�Ÿ귽�s�զC��C
                WafPolicies.Clear(); // �M�� WAF �����C��C
                ScanErrorOccurred = false;
                SelectedResourceGroupName = ""; // ���m�귽�s�տ�ܡC

                if (IsSubscriptionSelected)
                {
                    await LoadResourceGroupsAsync(SelectedTenantId, SelectedSubscriptionId); // ���J�ҿ�q�\�U���귽�s�աC
                    // ��ܭq�\��A���� WAF �������y�C
                    await PerformScanAsync(SelectedTenantId, SelectedSubscriptionId);
                }
                else // �p�G��ܤF "�Ҧ��q�\" �Ψ������
                {
                    // �p�G��ܡu�Ҧ��q�\�v�A�]���汽�y
                    await PerformScanAsync(SelectedTenantId, SelectedSubscriptionId); // SelectedSubscriptionId ����
                }
            }
            return Page(); // ��^��e�����C
        }

        // OnPostSelectResourceGroupAsync ��k�G�B�z�귽�s�տ�ܨƥ�C
        public async Task<IActionResult> OnPostSelectResourceGroupAsync()
        {
            await LoadTenantsAsync(); // ���s���J���Τ�C��C
            if (IsTenantSelected)
            {
                await LoadSubscriptionsAsync(SelectedTenantId); // ���J�q�\�C��C
                if (IsSubscriptionSelected)
                {
                    await LoadResourceGroupsAsync(SelectedTenantId, SelectedSubscriptionId); // ���J�귽�s�զC��C
                    WafPolicies.Clear(); // �M�� WAF �����C��C
                    ScanErrorOccurred = false;

                    if (IsResourceGroupSelected)
                    {
                        await PerformScanAsync(SelectedTenantId, SelectedSubscriptionId, SelectedResourceGroupName); // ���y�ҿ�귽�s�աC
                    }
                    else // �p�G��ܤF "�Ҧ��귽�s��" �Ψ������
                    {
                        await PerformScanAsync(SelectedTenantId, SelectedSubscriptionId); // ���y��ӭq�\�C
                    }
                }
            }
            return Page(); // ��^��e�����C
        }

        // LoadTenantsAsync ��k�G�q�A�ȸ��J�Ҧ��i�Ϊ����Τ�C
        private async Task LoadTenantsAsync()
        {
            var tenants = await _wafScannerService.GetAllAccessibleTenantsAsync();
            AvailableTenants = tenants.Select(t => new SelectListItem
            {
                Value = t.Id,
                Text = $"{t.DisplayName} ({t.Id})"
            }).ToList();

            // �b�C�����K�[�@�ӡu�п�ܯ��Τ�v���ﶵ
            AvailableTenants.Insert(0, new SelectListItem { Value = "", Text = "--- �п�ܯ��Τ� ---", Selected = true, Disabled = true });

            // �p�G SelectedTenantId ���b���ĦC���A�h���m��
            if (!string.IsNullOrEmpty(SelectedTenantId) && !AvailableTenants.Any(t => t.Value == SelectedTenantId))
            {
                SelectedTenantId = "";
            }
        }

        // LoadSubscriptionsAsync ��k�G�q�A�ȸ��J���w���Τ�U�Ҧ��i�Ϊ��q�\�C
        private async Task LoadSubscriptionsAsync(string tenantId)
        {
            if (string.IsNullOrEmpty(tenantId)) return; // �p�G�S����ܯ��Τ�A�h�����J�q�\�C

            var subscriptions = await _wafScannerService.GetAllAccessibleSubscriptionsAsync(tenantId);
            AvailableSubscriptions = subscriptions.Select(s => new SelectListItem
            {
                Value = s.Id,
                Text = $"{s.DisplayName} ({s.Id})"
            }).ToList();

            // �b�C�����K�[�@�ӡu�Ҧ��q�\�v���ﶵ
            AvailableSubscriptions.Insert(0, new SelectListItem { Value = "", Text = "--- �Ҧ��q�\ ---", Selected = true });

            // �p�G SelectedSubscriptionId ���b���ĦC���A�h���m��
            if (!string.IsNullOrEmpty(SelectedSubscriptionId) && !AvailableSubscriptions.Any(s => s.Value == SelectedSubscriptionId))
            {
                SelectedSubscriptionId = "";
            }
        }

        // LoadResourceGroupsAsync ��k�G�q�A�ȸ��J���w�q�\�U�]�t WAF �������귽�s�աC
        private async Task LoadResourceGroupsAsync(string tenantId, string subscriptionId)
        {
            if (string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(subscriptionId)) return; // �p�G�S����ܯ��Τ�έq�\�A�h�����J�귽�s�աC

            var resourceGroups = await _wafScannerService.GetResourceGroupsWithWafPoliciesAsync(tenantId, subscriptionId);
            AvailableResourceGroups = resourceGroups.Select(rg => new SelectListItem
            {
                Value = rg.Name,
                Text = rg.Name
            }).ToList();

            // �b�C�����K�[�@�ӡu�Ҧ��귽�s�աv���ﶵ
            AvailableResourceGroups.Insert(0, new SelectListItem { Value = "", Text = "--- �Ҧ��귽�s�� ---", Selected = true });

            // �p�G SelectedResourceGroupName ���b���ĦC���A�h���m��
            if (!string.IsNullOrEmpty(SelectedResourceGroupName) && !AvailableResourceGroups.Any(rg => rg.Value == SelectedResourceGroupName))
            {
                SelectedResourceGroupName = "";
            }
        }

        // PerformScanAsync ��k�G���� WAF �������y���֤��޿�C
        private async Task PerformScanAsync(string tenantId, string subscriptionId, string resourceGroupName = null)
        {
            // �u����P�ɿ�ܤF���Τ�M�q�\�ɤ~���汽�y�C
            if (string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(subscriptionId))
            {
                WafPolicies.Clear();
                ScanErrorOccurred = false; // �S����������ܡA������~�A�u�O�S���ƾ�
                return;
            }

            try
            {
                _logger.LogInformation($"���b���� WAF �������y (���Τ�: {tenantId}, �q�\: {subscriptionId ?? "�Ҧ�"}, �귽�s��: {resourceGroupName ?? "�Ҧ�"}) ...");
                WafPolicies = await _wafScannerService.ScanWafPoliciesAsync(tenantId, subscriptionId, resourceGroupName);
                ScanErrorOccurred = false;
                _logger.LogInformation($"WAF �������y�����A��� {WafPolicies.Count} �ӵ����C");
            }
            catch (Exception ex)
            {
                _logger.LogError($"���y WAF �����ɵo�Ϳ��~: {ex.Message}");
                ScanErrorOccurred = true;
                WafPolicies.Clear(); // ���y���ѮɲM�ŵ��G
            }
        }
    }
}