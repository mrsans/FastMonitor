import axios from 'axios';
import {hideLoading, showLoading} from '@/util/loading'
import tip from '@/util/tip_util';
import router from '@/router'
import qs from 'qs';

const defaultUrl = ""; // process.env.NODE_ENV == "development" ? "/api" : "/xr-api";

/**
 * 创建初始化对象
 */
const api = axios.create({
    baseUrl: defaultUrl,
    timeout: 1000 * 60
});

/**
 * 请求拦截器
 */
api.interceptors.request.use(config => {
    if (!config.showLoading) {
        showLoading();
    }
    config.headers['token'] = localStorage.getItem('token');
    return config;
}, err => Promise.reject(err));

/**
 * 全局响应拦截器
 */
api.interceptors.response.use(response => {
        if (!response.config.showLoading) {
            hideLoading();
        }
        if (response.status === 200) {
            return response.data;
        } else {
            let message = response.data.message;
            if (message) {
                tip.error(message);
            } else {
                tip.error('后台异常');
            }
        }
    },
    error => {
        if (!error.config || !error.config.showLoading) {
            hideLoading();
        }
        switch (error.response.status) {
            case 401: // 跳转登录
            {
                router.replace("/");
                break;
            }
            case 404: // 页面错误
            {
                tip.error("地址不存在");
                break;
            }
            case 500: // 后台异常
            {
                let message = error.response.data.message || '后台异常';
                tip.error(message);
                break;
            }
        }
    }
);

/**
 *
 * @param {String} url 地址
 * @param {Object} params 参数
 * @returns
 */
function post(url, params) {
    return api({
        url: defaultUrl + url,
        method: "POST",
        headers: {'Content-Type': 'multipart/form-data'},
        data: params
    });
}

/**
 * get请求
 * @param {String} url 地址
 * @param {Object} params 参数
 * @returns
 */
function get(url, params) {
    return api.get(defaultUrl + url + "?" + qs.stringify(params));
}

function getNoLoading(url, params) {
    return api.get(defaultUrl + url + "?" + qs.stringify(params), {
        showLoading: true
    });
}


/**
 * 发送json请求
 */
function postJson(url, data) {
    return api({
        url: defaultUrl + url,
        method: "POST",
        headers: {'Content-Type': 'application/json;charset=UTF-8'},
        data: JSON.stringify(data)
    });
}

/**
 * 预览
 * @param {*} url 下载地址
 * @param {*} filename 文件名称
 * @returns
 */
function downLoadFile(url, filename) {
    return new Promise((resolve, reject) => {
        axios({
            method: 'get',
            url: url,
            responseType: 'blob'
        }).then(response => {
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute("download", filename);
            document.body.appendChild(link);
            link.click();
            resolve();
        }).catch((error) => {
            reject(error);
            console.error('文件下载失败', error);
        });
    })
}

export default {
    get, post, postJson, downLoadFile, getNoLoading
}