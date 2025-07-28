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

    var notesModalElement = document.getElementById('notesModal');
    var notesModal = new bootstrap.Modal(notesModalElement);

    // 用於儲存當前點擊的「編輯備註」按鈕的引用
    var currentEditButton = null;

    $(document).on('click', '.edit-notes-btn', function () {
        currentEditButton = $(this); // 儲存按鈕引用
        var entityType = currentEditButton.data('entity-type');
        var currentNotes = currentEditButton.data('current-notes') || '';

        // 清空所有隱藏欄位，避免上一次點擊的殘留資料
        $('#notesPolicyName, #notesCustomRuleName, #notesMatchConditionIndex, #notesMatchValue, ' +
            '#notesManagedRuleSetType, #notesManagedRuleSetVersion, #notesRuleGroupName, #notesRuleId').val('');

        // 根據實體類型填充不同的隱藏欄位
        if (entityType === 'WafPolicy') {
            $('#notesModalLabel').text('編輯策略備註');
            $('#notesPolicyName').val(currentEditButton.data('entity-id'));
        } else if (entityType === 'CustomRule') {
            $('#notesModalLabel').text('編輯自訂規則備註');
            $('#notesPolicyName').val(currentEditButton.data('policy-name')); // 從 data-policy-name 獲取
            $('#notesCustomRuleName').val(currentEditButton.data('custom-rule-name')); // 從 data-custom-rule-name 獲取
        } else if (entityType === 'ManagedRuleOverride') {
            $('#notesModalLabel').text('編輯託管規則覆寫備註');
            // *** 直接從 data-* 屬性讀取 ***
            $('#notesPolicyName').val(currentEditButton.data('policy-name'));
            $('#notesManagedRuleSetType').val(currentEditButton.data('ruleset-type'));
            $('#notesManagedRuleSetVersion').val(currentEditButton.data('ruleset-version'));
            $('#notesRuleGroupName').val(currentEditButton.data('rule-group-name'));
            $('#notesRuleId').val(currentEditButton.data('rule-id')); // 直接獲取 RuleId
        } else if (entityType === 'MatchValue') {
            $('#notesModalLabel').text('編輯匹配值備註');
            $('#notesPolicyName').val(currentEditButton.data('policy-name'));
            $('#notesCustomRuleName').val(currentEditButton.data('custom-rule-name'));
            $('#notesMatchConditionIndex').val(currentEditButton.data('match-condition-index'));
            $('#notesMatchValue').val(currentEditButton.data('match-value'));
        }

        // 設定通用欄位
        $('#notesEntityType').val(entityType);
        $('#notesTextarea').val(currentNotes);

        notesModal.show();
    });

    // 監聽模態視窗的儲存按鈕點擊事件
    $('#saveNotesBtn').on('click', function () {
        var entityType = $('#notesEntityType').val();
        var newNotes = $('#notesTextarea').val();
        var postData = {
            notesContent: newNotes,
            entityType: entityType
        };

        // 根據實體類型組裝不同的鍵值到 postData
        if (entityType === 'WafPolicy') {
            postData.wafPolicyName = $('#notesPolicyName').val();
            // PartitionKey: policy.Name, RowKey: "" (或也用 policy.Name)
            postData.partitionKey = postData.wafPolicyName;
            postData.rowKey = postData.wafPolicyName; // 或一個固定字串如 "PolicyNotes"
        } else if (entityType === 'CustomRule') {
            postData.wafPolicyName = $('#notesPolicyName').val();
            postData.customRuleName = $('#notesCustomRuleName').val();
            // PartitionKey: PolicyName_CustomRuleName, RowKey: CustomRuleName (或一個固定字串如 "RuleNotes")
            postData.partitionKey = `${postData.wafPolicyName}_${postData.customRuleName}`;
            postData.rowKey = postData.customRuleName; // 或一個固定字串如 "RuleNotes"
        } else if (entityType === 'ManagedRuleOverride') {
            postData.wafPolicyName = $('#notesPolicyName').val();
            postData.managedRuleSetType = $('#notesManagedRuleSetType').val();
            postData.managedRuleSetVersion = $('#notesManagedRuleSetVersion').val();
            postData.ruleGroupName = $('#notesRuleGroupName').val();
            postData.ruleId = $('#notesRuleId').val(); // 確保這裡取得了正確的 RuleId

            // Construct PartitionKey and RowKey carefully
            postData.partitionKey = `${postData.wafPolicyName}_${postData.managedRuleSetType}_${postData.managedRuleSetVersion}_${postData.ruleGroupName}`;
            // *** 關鍵：對 RowKey 進行 URL 編碼 ***
            postData.rowKey = encodeURIComponent(postData.ruleId);
        } else if (entityType === 'MatchValue') {
            postData.wafPolicyName = $('#notesPolicyName').val();
            postData.customRuleName = $('#notesCustomRuleName').val();
            postData.matchConditionIndex = $('#notesMatchConditionIndex').val();
            postData.matchValue = $('#notesMatchValue').val();

            // 對 matchValue 進行 URL 編碼以用於 RowKey
            var encodedMatchValue = encodeURIComponent(postData.matchValue);

            // PartitionKey: PolicyName_CustomRuleName
            // RowKey: MatchConditionIndex_EncodedMatchValue
            postData.partitionKey = `${postData.wafPolicyName}_${postData.customRuleName}`;
            postData.rowKey = `MC_${postData.matchConditionIndex}_${encodedMatchValue}`;
        }

        // 從 currentEditButton 獲取目標元素的 ID
        var targetNotesId = currentEditButton.data('target-notes-id');
        var targetContainerId = currentEditButton.data('target-container-id');
        var targetBadgeId = currentEditButton.data('target-badge-id'); // 新增的備註徽章ID

        // 發送 AJAX 請求到後端來保存備註
        $.ajax({
            url: '/api/wafnotes/save',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(postData),
            success: function (response) {
                alert('備註已保存！');
                /// *** UI 更新邏輯 ***
                if (targetNotesId) {
                    var $notesContentSpan = $('#' + targetNotesId);
                    var $notesContainerDiv = targetContainerId ? $('#' + targetContainerId) : null;
                    var $notesBadgeSpan = targetBadgeId ? $('#' + targetBadgeId) : null;

                    if (newNotes && newNotes.trim() !== '') {
                        $notesContentSpan.text(newNotes);
                        if ($notesContainerDiv) {
                            $notesContainerDiv.show();
                        }
                        if ($notesBadgeSpan) { 
                            $notesBadgeSpan.show();
                        }
                    } else {
                        $notesContentSpan.text('');
                        if ($notesContainerDiv) {
                            $notesContainerDiv.hide();
                        }
                        if ($notesBadgeSpan) { 
                            $notesBadgeSpan.hide();
                        }
                    }
                }

                // 更新按鈕的 data-current-notes 屬性，以便下次編輯時顯示最新內容
                currentEditButton.data('current-notes', newNotes);

                notesModal.hide();
            },
            error: function (xhr, status, error) {
                alert('保存備註失敗: ' + (xhr.responseJSON ? xhr.responseJSON.message : error));
            }
        });
    });

    // 模態視窗關閉時清除文字區域內容
    notesModalElement.addEventListener('hidden.bs.modal', function (event) {
        $('#notesTextarea').val('');
        currentEditButton = null; // 清除按鈕引用
    });
});