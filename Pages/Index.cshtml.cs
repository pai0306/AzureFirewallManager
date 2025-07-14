using AzureFirewallManagerTools.Models;
using AzureFirewallManagerTools.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using System.Collections.Generic;
using System.Text.Json;
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
        public string ErrorMessage { get; set; }

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
            /*if (IsTenantSelected)
            {
                await LoadSubscriptionsAsync(SelectedTenantId);
                if (IsSubscriptionSelected)
                {
                    await LoadResourceGroupsAsync(SelectedTenantId, SelectedSubscriptionId);
                    // �p�G���w�諸���Τ�M�q�\�A�h�b OnGet �ɰ���@�����y
                    // �o�˷�Τ᪽���X�ݱa���Ѽƪ� URL �ɡA�]����ܼƾڡC
                    await PerformScanAsync(SelectedTenantId, SelectedSubscriptionId, SelectedResourceGroupName);
                }
            }*/
        }

        // OnPostSelectTenantAsync ��k�G�B�z���Τ��ܨƥ�C
        public async Task<IActionResult> OnPostSelectTenantAsync()
        {
            AvailableSubscriptions.Clear(); // �M�ŭq�\�C��C
            AvailableResourceGroups.Clear(); // �M�Ÿ귽�s�զC��C
            WafPolicies.Clear(); // �M�� WAF �����C��C
            ScanErrorOccurred = false;
            ErrorMessage = null;
            SelectedSubscriptionId = ""; // ���m�q�\��ܡC
            SelectedResourceGroupName = ""; // ���m�귽�s�տ�ܡC

            if (!string.IsNullOrEmpty(SelectedTenantId))
            {
                try
                {
                    await LoadSubscriptionsAsync(SelectedTenantId);
                    // �ھڳ]�p�A��ܯ���ᤣ�ߧY���y WAF
                    WafPolicies = new List<WafPolicyDetails>(); // �T�O�M��
                    return new JsonResult(new
                    {
                        Success = true,
                        Subscriptions = AvailableSubscriptions
                    });
                }
                catch (Exception ex)
                {
                    ScanErrorOccurred = true;
                    ErrorMessage = $"���J�q�\�ɵo�Ϳ��~: {ex.Message}";
                    Console.WriteLine(ErrorMessage);
                    return new JsonResult(new { Success = false, ErrorMessage = ErrorMessage });
                }
            }
            return new JsonResult(new { Success = true, Subscriptions = new List<object>() }); // �p�G�S����ܯ���A��^�ŦC��
        }

        // OnPostSelectSubscriptionAsync ��k�G�B�z�q�\��ܨƥ�C
        public async Task<IActionResult> OnPostSelectSubscriptionAsync()
        {
            AvailableResourceGroups.Clear(); // �M�Ÿ귽�s�զC��C
            WafPolicies.Clear(); // �M�� WAF �����C��C
            ScanErrorOccurred = false;
            SelectedResourceGroupName = ""; // ���m�귽�s�տ�ܡC

            if (!string.IsNullOrWhiteSpace(SelectedSubscriptionId))
            {
                try
                {
                    await LoadResourceGroupsAsync(SelectedTenantId, SelectedSubscriptionId); // ���J�ҿ�q�\�U���귽�s�աC

                    // ��ܭq�\��A���� WAF �������y�C
                    await PerformScanAsync(SelectedTenantId, SelectedSubscriptionId);

                    // �N WAF ��������V�� HTML �r��
                    // �ݭn�@�� _WafPoliciesTablePartial.cshtml ��������
                    var wafPoliciesHtml = await RenderPartialViewToStringAsync("_WafPoliciesPartial", WafPolicies);

                    return new JsonResult(new
                    {
                        Success = true,
                        ResourceGroups = AvailableResourceGroups,
                        WafPoliciesHtml = wafPoliciesHtml
                    });
                }
                catch (Exception ex)
                {
                    ScanErrorOccurred = true;
                    ErrorMessage = $"���J�q�\�ɵo�Ϳ��~: {ex.Message}";
                    Console.WriteLine(ErrorMessage);
                    return new JsonResult(new { Success = false, ErrorMessage = ErrorMessage });
                }
            }
            else {
                return new JsonResult(new { Success = true, ResourceGroups = new List<object>() }); // �p�G�S����ܭq�\�A��^�ŦC��
            }
        }

        // OnPostSelectResourceGroupAsync ��k�G�B�z�귽�s�տ�ܨƥ�C
        public async Task<IActionResult> OnPostSelectResourceGroupAsync()
        {
            WafPolicies.Clear(); // �M�� WAF �����C��C
            ScanErrorOccurred = false;

            if (!string.IsNullOrWhiteSpace(SelectedSubscriptionId))
            {
                try
                {
                    await PerformScanAsync(SelectedTenantId, SelectedSubscriptionId, SelectedResourceGroupName); // ���y�ҿ�귽�s�աC

                    // �N WAF ��������V�� HTML �r��
                    // �ݭn�@�� _WafPoliciesTablePartial.cshtml ��������
                    var wafPoliciesHtml = await RenderPartialViewToStringAsync("_WafPoliciesPartial", WafPolicies);

                    return new JsonResult(new
                    {
                        Success = true,
                        WafPoliciesHtml = wafPoliciesHtml
                    });
                } catch (Exception ex)
                {
                    ScanErrorOccurred = true;
                    ErrorMessage = $"���J�q�\�ɵo�Ϳ��~: {ex.Message}";
                    Console.WriteLine(ErrorMessage);
                    return new JsonResult(new { Success = false, ErrorMessage = ErrorMessage });
                }
            } else
            {
                return new JsonResult(new { Success = true, WafPoliciesHtml = "" }); // �p�G�S����ܭq�\�A��^�ŦC��
            }
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

        private async Task<string> RenderPartialViewToStringAsync<TModel>(string viewName, TModel model)
        {
            var viewData = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
            {
                Model = model
            };

            using (var writer = new StringWriter())
            {
                var viewEngine = HttpContext.RequestServices.GetService(typeof(IRazorViewEngine)) as IRazorViewEngine;
                var actionContext = new ActionContext(HttpContext, RouteData, PageContext.ActionDescriptor);
                var viewResult = viewEngine.FindView(actionContext, viewName, false);

                if (viewResult.View == null)
                {
                    throw new ArgumentNullException($"{viewName} does not match any available view");
                }

                var viewContext = new ViewContext(
                    actionContext,
                    viewResult.View,
                    viewData,
                    TempData,
                    writer,
                    new HtmlHelperOptions()
                );

                await viewResult.View.RenderAsync(viewContext);

                return writer.GetStringBuilder().ToString();
            }
        }

    }
}