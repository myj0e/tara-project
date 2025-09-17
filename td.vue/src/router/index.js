import Vue from 'vue';
import VueRouter from 'vue-router';

import { gitRoutes } from './git.js';
import HomePage from '../views/HomePage.vue';
import { localRoutes } from './local.js';
import { desktopRoutes } from './desktop.js';
import { googleRoutes } from './google.js';
// 添加新页面的导入
import ShowDREAD from '../views/showDREAD.vue';
import ShowMitigations from '../views/ShowMitigations.vue'; // 添加这一行
import Agent from '../views/Agent.vue'; // 添加Agent组件导入

const routes = [
    {
        path: '/',
        name: 'HomePage',
        component: HomePage
    },
    {
        path: '/dashboard',
        name: 'MainDashboard',
        component: () => import(/* webpackChunkName: "main-dashboard" */ '../views/MainDashboard.vue')
    },
    {
        path: '/oauth-return',
        name: 'OAuthReturn',
        component: () => import(/* webpackChunkName: "oauth-return" */ '../views/OauthReturn.vue')
    },
    {
        path: '/demo/select',
        name: 'DemoSelect',
        component: () => import(/* webpackChunkName: "demo-select" */ '../views/demo/SelectDemoModel.vue')
    },
    // 添加新路由
    {
        path: '/show-dread',  // 新页面的路径
        name: 'ShowDREAD',    // 路由名称
        component: ShowDREAD  // 新页面组件
    },
    {
        path: '/mitigations',  // 缓解措施页面的路径
        name: 'ShowMitigations',    // 路由名称
        component: ShowMitigations  // 缓解措施页面组件
    },
    {
        path: '/agent',  // Agent页面的路径
        name: 'Agent',    // 路由名称
        component: Agent  // Agent页面组件
    },
    ...desktopRoutes,
    ...gitRoutes,
    ...localRoutes,
    ...googleRoutes
];

const get = () => {
    Vue.use(VueRouter);
    const router = new VueRouter({
        routes
    });
    return router;
};

export default {
    get
};