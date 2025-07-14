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
        private readonly ILogger<IndexModel> _logger; // 日誌記錄器。
        private readonly AzureWafScannerService _wafScannerService; // WAF 掃描服務的實例。

        // 綁定屬性，用於在頁面顯示 WAF 策略列表。
        [BindProperty]
        public List<WafPolicyDetails> WafPolicies { get; set; } = new List<WafPolicyDetails>();

        // 綁定屬性，用於下拉選單中選定的租用戶 ID。
        [BindProperty]
        public string SelectedTenantId { get; set; }

        // 綁定屬性，用於下拉選單中選定的訂閱 ID。
        [BindProperty]
        public string SelectedSubscriptionId { get; set; }

        // 綁定屬性，用於下拉選單中選定的資源群組名稱。
        [BindProperty]
        public string SelectedResourceGroupName { get; set; }

        // 可用的租用戶列表，用於下拉選單。
        public List<SelectListItem> AvailableTenants { get; set; } = new List<SelectListItem>();

        // 可用的訂閱列表，用於下拉選單。
        public List<SelectListItem> AvailableSubscriptions { get; set; } = new List<SelectListItem>();

        // 可用的資源群組列表，用於下拉選單。
        public List<SelectListItem> AvailableResourceGroups { get; set; } = new List<SelectListItem>();

        // 標記掃描是否發生錯誤，用於在 UI 上顯示錯誤訊息。
        public bool ScanErrorOccurred { get; set; } = false;
        public string ErrorMessage { get; set; }

        // 標記是否已選擇租用戶。
        public bool IsTenantSelected => !string.IsNullOrEmpty(SelectedTenantId);

        // 標記是否已選擇訂閱。
        public bool IsSubscriptionSelected => !string.IsNullOrEmpty(SelectedSubscriptionId);

        // 標記是否已選擇資源群組。
        public bool IsResourceGroupSelected => !string.IsNullOrEmpty(SelectedResourceGroupName);

        // 建構函式：透過依賴注入接收日誌記錄器和 WAF 掃描服務。
        public IndexModel(ILogger<IndexModel> logger, AzureWafScannerService wafScannerService)
        {
            _logger = logger;
            _wafScannerService = wafScannerService;
        }

        // OnGetAsync 方法：當頁面初次載入時執行。
        public async Task OnGetAsync()
        {
            await LoadTenantsAsync(); // 首先載入所有可用的租用戶。

            // 在此階段，不執行 WAF 策略掃描，只準備下拉選單。
            /*if (IsTenantSelected)
            {
                await LoadSubscriptionsAsync(SelectedTenantId);
                if (IsSubscriptionSelected)
                {
                    await LoadResourceGroupsAsync(SelectedTenantId, SelectedSubscriptionId);
                    // 如果有預選的租用戶和訂閱，則在 OnGet 時執行一次掃描
                    // 這樣當用戶直接訪問帶有參數的 URL 時，也能顯示數據。
                    await PerformScanAsync(SelectedTenantId, SelectedSubscriptionId, SelectedResourceGroupName);
                }
            }*/
        }

        // OnPostSelectTenantAsync 方法：處理租用戶選擇事件。
        public async Task<IActionResult> OnPostSelectTenantAsync()
        {
            AvailableSubscriptions.Clear(); // 清空訂閱列表。
            AvailableResourceGroups.Clear(); // 清空資源群組列表。
            WafPolicies.Clear(); // 清空 WAF 策略列表。
            ScanErrorOccurred = false;
            ErrorMessage = null;
            SelectedSubscriptionId = ""; // 重置訂閱選擇。
            SelectedResourceGroupName = ""; // 重置資源群組選擇。

            if (!string.IsNullOrEmpty(SelectedTenantId))
            {
                try
                {
                    await LoadSubscriptionsAsync(SelectedTenantId);
                    // 根據設計，選擇租戶後不立即掃描 WAF
                    WafPolicies = new List<WafPolicyDetails>(); // 確保清空
                    return new JsonResult(new
                    {
                        Success = true,
                        Subscriptions = AvailableSubscriptions
                    });
                }
                catch (Exception ex)
                {
                    ScanErrorOccurred = true;
                    ErrorMessage = $"載入訂閱時發生錯誤: {ex.Message}";
                    Console.WriteLine(ErrorMessage);
                    return new JsonResult(new { Success = false, ErrorMessage = ErrorMessage });
                }
            }
            return new JsonResult(new { Success = true, Subscriptions = new List<object>() }); // 如果沒有選擇租戶，返回空列表
        }

        // OnPostSelectSubscriptionAsync 方法：處理訂閱選擇事件。
        public async Task<IActionResult> OnPostSelectSubscriptionAsync()
        {
            AvailableResourceGroups.Clear(); // 清空資源群組列表。
            WafPolicies.Clear(); // 清空 WAF 策略列表。
            ScanErrorOccurred = false;
            SelectedResourceGroupName = ""; // 重置資源群組選擇。

            if (!string.IsNullOrWhiteSpace(SelectedSubscriptionId))
            {
                try
                {
                    await LoadResourceGroupsAsync(SelectedTenantId, SelectedSubscriptionId); // 載入所選訂閱下的資源群組。

                    // 選擇訂閱後，執行 WAF 策略掃描。
                    await PerformScanAsync(SelectedTenantId, SelectedSubscriptionId);

                    // 將 WAF 策略表格渲染為 HTML 字串
                    // 需要一個 _WafPoliciesTablePartial.cshtml 局部視圖
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
                    ErrorMessage = $"載入訂閱時發生錯誤: {ex.Message}";
                    Console.WriteLine(ErrorMessage);
                    return new JsonResult(new { Success = false, ErrorMessage = ErrorMessage });
                }
            }
            else {
                return new JsonResult(new { Success = true, ResourceGroups = new List<object>() }); // 如果沒有選擇訂閱，返回空列表
            }
        }

        // OnPostSelectResourceGroupAsync 方法：處理資源群組選擇事件。
        public async Task<IActionResult> OnPostSelectResourceGroupAsync()
        {
            WafPolicies.Clear(); // 清空 WAF 策略列表。
            ScanErrorOccurred = false;

            if (!string.IsNullOrWhiteSpace(SelectedSubscriptionId))
            {
                try
                {
                    await PerformScanAsync(SelectedTenantId, SelectedSubscriptionId, SelectedResourceGroupName); // 掃描所選資源群組。

                    // 將 WAF 策略表格渲染為 HTML 字串
                    // 需要一個 _WafPoliciesTablePartial.cshtml 局部視圖
                    var wafPoliciesHtml = await RenderPartialViewToStringAsync("_WafPoliciesPartial", WafPolicies);

                    return new JsonResult(new
                    {
                        Success = true,
                        WafPoliciesHtml = wafPoliciesHtml
                    });
                } catch (Exception ex)
                {
                    ScanErrorOccurred = true;
                    ErrorMessage = $"載入訂閱時發生錯誤: {ex.Message}";
                    Console.WriteLine(ErrorMessage);
                    return new JsonResult(new { Success = false, ErrorMessage = ErrorMessage });
                }
            } else
            {
                return new JsonResult(new { Success = true, WafPoliciesHtml = "" }); // 如果沒有選擇訂閱，返回空列表
            }
        }
        // LoadTenantsAsync 方法：從服務載入所有可用的租用戶。
        private async Task LoadTenantsAsync()
        {
            var tenants = await _wafScannerService.GetAllAccessibleTenantsAsync();
            AvailableTenants = tenants.Select(t => new SelectListItem
            {
                Value = t.Id,
                Text = $"{t.DisplayName} ({t.Id})"
            }).ToList();

            // 在列表頂部添加一個「請選擇租用戶」的選項
            AvailableTenants.Insert(0, new SelectListItem { Value = "", Text = "--- 請選擇租用戶 ---", Selected = true, Disabled = true });

            // 如果 SelectedTenantId 不在有效列表內，則重置它
            if (!string.IsNullOrEmpty(SelectedTenantId) && !AvailableTenants.Any(t => t.Value == SelectedTenantId))
            {
                SelectedTenantId = "";
            }
        }

        // LoadSubscriptionsAsync 方法：從服務載入指定租用戶下所有可用的訂閱。
        private async Task LoadSubscriptionsAsync(string tenantId)
        {
            if (string.IsNullOrEmpty(tenantId)) return; // 如果沒有選擇租用戶，則不載入訂閱。

            var subscriptions = await _wafScannerService.GetAllAccessibleSubscriptionsAsync(tenantId);
            AvailableSubscriptions = subscriptions.Select(s => new SelectListItem
            {
                Value = s.Id,
                Text = $"{s.DisplayName} ({s.Id})"
            }).ToList();

            // 如果 SelectedSubscriptionId 不在有效列表內，則重置它
            if (!string.IsNullOrEmpty(SelectedSubscriptionId) && !AvailableSubscriptions.Any(s => s.Value == SelectedSubscriptionId))
            {
                SelectedSubscriptionId = "";
            }
        }

        // LoadResourceGroupsAsync 方法：從服務載入指定訂閱下包含 WAF 策略的資源群組。
        private async Task LoadResourceGroupsAsync(string tenantId, string subscriptionId)
        {
            if (string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(subscriptionId)) return; // 如果沒有選擇租用戶或訂閱，則不載入資源群組。

            var resourceGroups = await _wafScannerService.GetResourceGroupsWithWafPoliciesAsync(tenantId, subscriptionId);
            AvailableResourceGroups = resourceGroups.Select(rg => new SelectListItem
            {
                Value = rg.Name,
                Text = rg.Name
            }).ToList();

            // 在列表頂部添加一個「所有資源群組」的選項
            AvailableResourceGroups.Insert(0, new SelectListItem { Value = "", Text = "--- 所有資源群組 ---", Selected = true });

            // 如果 SelectedResourceGroupName 不在有效列表內，則重置它
            if (!string.IsNullOrEmpty(SelectedResourceGroupName) && !AvailableResourceGroups.Any(rg => rg.Value == SelectedResourceGroupName))
            {
                SelectedResourceGroupName = "";
            }
        }

        // PerformScanAsync 方法：執行 WAF 策略掃描的核心邏輯。
        private async Task PerformScanAsync(string tenantId, string subscriptionId, string resourceGroupName = null)
        {
            // 只有當同時選擇了租用戶和訂閱時才執行掃描。
            if (string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(subscriptionId))
            {
                WafPolicies.Clear();
                ScanErrorOccurred = false; // 沒有足夠的選擇，不算錯誤，只是沒有數據
                return;
            }

            try
            {
                _logger.LogInformation($"正在執行 WAF 策略掃描 (租用戶: {tenantId}, 訂閱: {subscriptionId ?? "所有"}, 資源群組: {resourceGroupName ?? "所有"}) ...");
                WafPolicies = await _wafScannerService.ScanWafPoliciesAsync(tenantId, subscriptionId, resourceGroupName);
                ScanErrorOccurred = false;
                _logger.LogInformation($"WAF 策略掃描完成，找到 {WafPolicies.Count} 個策略。");
            }
            catch (Exception ex)
            {
                _logger.LogError($"掃描 WAF 策略時發生錯誤: {ex.Message}");
                ScanErrorOccurred = true;
                WafPolicies.Clear(); // 掃描失敗時清空結果
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