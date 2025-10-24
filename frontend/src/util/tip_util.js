import { ElMessage, ElMessageBox } from 'element-plus'

/**
 * 错误提示
 */
function error(message) {
    ElMessage.success({
        showClose: true,
        message: message,
        type: 'error'
    });
}

/**
 * 成功提示
 */
function success(message) {
    ElMessage({
        showClose: true,
        message: message,
        type: 'success'
    });
}

/**
 * 警告提示
 */
function warn(message) {
    ElMessage({
        showClose: true,
        message: message,
        type: 'warning'
    });
}

/**
 * 确认警告框
 * @param {String} tip 提示信息 
 * @param {Function} fun 函数信息
 */
function confirm(tip, fun, cancelFun = null) {
    ElMessageBox.confirm(tip, "提示", {
        confirmButtonText: "确定",
        cancelButtonText: "取消",
        type: "warning",
        closeOnClickModal: false
    }).then(() => fun())
    .catch(() => {
        if (cancelFun) {
            cancelFun();
        }
    });
}

export default {
    error,
    warn,
    success,
    confirm
}