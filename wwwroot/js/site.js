$(function () {
    // 統一處理載入指示器和遮罩的函數
    function showLoading() {
        $('#loadingSpinner').show();
        // 檢查是否已存在遮罩，避免重複添加
        if ($('.loading-overlay').length === 0) {
            $('body').append('<div class="loading-overlay"></div>');
        }
    }

    function hideLoading() {
        $('#loadingSpinner').hide();
        $('.loading-overlay').remove();
    }

    $("#SelectedTenantId").on("change", function () {
        showLoading();
        $("#IsTenantSelected").hide();
        $('#wafPoliciesTableContainer').hide();

        var selectedTenantId = $('#SelectedTenantId').val();

        if (selectedTenantId !== "") {
            $.ajax({
                url: '?handler=SelectTenant',
                type: 'POST',
                data: { SelectedTenantId: selectedTenantId },
                headers: {
                    RequestVerificationToken: $('input[name="__RequestVerificationToken"]').val() // 包含 CSRF token
                },
                success: function (response) {
                    if (response.success) {
                        var subDropdown = $('#SelectedSubscriptionId');
                        subDropdown.empty().append('<option value="">-- 請選擇訂閱 --</option>'); // 重置選項

                        $('#SelectedResourceGroupName').empty().attr('disabled', 'true').append('<option value="">--- 請先選擇訂閱 ---</option>');

                        // 填充訂閱下拉選單
                        if (response.subscriptions && response.subscriptions.length > 0) {
                            $.each(response.subscriptions, function (index, item) {
                                subDropdown.append($('<option></option>').val(item.value).text(item.text));
                            });
                            subDropdown.prop('disabled', false); // 啟用訂閱下拉選單
                        } else {
                            subDropdown.prop('disabled', true); // 如果沒有訂閱，保持禁用
                            subDropdown.append('<option>無可用訂閱</option>');
                        }

                        $("#IsSubScriptionSeleted").show();
                    } else {
                        $("#IsTenantSelected").show();
                        alert('載入訂閱失敗。');
                        console.error("Error loading subscriptions:", response);
                    }
                    hideLoading();
                },
                error: function (xhr) {
                    hideLoading();
                    $("#IsTenantSelected").show();
                    alert('選擇租戶時發生錯誤: ' + xhr.responseText);
                }
            });
        }
    });

    $("#SelectedSubscriptionId").on("change", function () {
        showLoading();
        $("#IsTenantSelected").hide();
        $("#IsSubScriptionSeleted").hide();

        var selectedSubscriptionId = $('#SelectedSubscriptionId').val();
        var selectedTenantId = $('#SelectedTenantId').val();

        $.ajax({
            url: '?handler=SelectSubscription',
            type: 'POST',
            data: { SelectedSubscriptionId: selectedSubscriptionId, SelectedTenantId: selectedTenantId },
            headers: {
                RequestVerificationToken: $('input[name="__RequestVerificationToken"]').val() // 包含 CSRF token
            },
            success: function (response) {
                if (response.success) {
                    var subDropdown = $('#SelectedResourceGroupName');
                    subDropdown.empty().append('<option value="" disabled>-- 請選擇資源群組 --</option>'); // 重置選項

                    // 填充訂閱下拉選單
                    if (response.resourceGroups && response.resourceGroups.length > 0) {
                        $.each(response.resourceGroups, function (index, item) {
                            subDropdown.append($('<option></option>').val(item.value).text(item.text));
                        });
                        subDropdown.prop('disabled', false); // 啟用訂閱下拉選單
                    } else {
                        subDropdown.prop('disabled', true); // 如果沒有資源群組，保持禁用
                        subDropdown.append('<option>無可用資源群組</option>');
                    }

                    if (response.wafPoliciesHtml) {
                        $('#wafPoliciesTableContainer').html(response.wafPoliciesHtml);
                        $('#wafPoliciesTableContainer').show();
                    }

                } else {
                    $("#IsSubScriptionSeleted").show();
                    alert('載入資源失敗。');
                    console.error("Error loading resources:", response);
                }

                hideLoading();
            },
            error: function (xhr) {
                $("#IsSubScriptionSeleted").show();
                hideLoading();
                alert('選擇訂閱時發生錯誤: ' + xhr.responseText);
            }
        });
    });

    // 資源群組下拉選單
    $("#SelectedResourceGroupName").on("change", function () {
        showLoading();
        $('#wafPoliciesTableContainer').hide();
        $("#IsTenantSelected").hide();
        $("#IsSubScriptionSeleted").hide();

        var selectedSubscriptionId = $('#SelectedSubscriptionId').val();
        var selectedTenantId = $('#SelectedTenantId').val();
        var selectedResourceGroupName = $('#SelectedResourceGroupName').val();

        $.ajax({
            url: '?handler=SelectResourceGroup',
            type: 'POST',
            data: { SelectedSubscriptionId: selectedSubscriptionId, SelectedTenantId: selectedTenantId, SelectedResourceGroupName: selectedResourceGroupName },
            headers: {
                RequestVerificationToken: $('input[name="__RequestVerificationToken"]').val() // 包含 CSRF token
            },
            success: function (response) {
                if (response.success) {
                    if (response.wafPoliciesHtml) {
                        $('#wafPoliciesTableContainer').html(response.wafPoliciesHtml);
                        $('#wafPoliciesTableContainer').show();
                    } else if (response.wafPoliciesEmpty) {
                        $('#wafPoliciesTableContainer').html('<p>無可用WAF策略。</p>');
                        $('#wafPoliciesTableContainer').show();

                    }
                } else {
                    alert('載入Waf策略失敗。');
                    console.error("Error loading resources:", response);
                }

                hideLoading();
            },
            error: function (xhr) {
                hideLoading();
                alert('選擇資源群組時發生錯誤: ' + xhr.responseText);
            }
        });
    });
});