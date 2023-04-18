import { createApp } from 'vue'
import PrimeVue from 'primevue/config';
import { createPinia } from 'pinia'
import App from './App.vue'

import './assets/main.css'
import "primevue/resources/themes/vela-blue/theme.css";
import "primevue/resources/primevue.min.css";
import "primeicons/primeicons.css";
import "primeflex/primeflex.css";
import ToastService from 'primevue/toastservice';
import DialogService from 'primevue/dialogservice';
import ConfirmationService from 'primevue/confirmationservice';

import Button from 'primevue/button';
import Card from 'primevue/card';
import Checkbox from 'primevue/checkbox';
import ConfirmDialog from 'primevue/confirmdialog';
import DynamicDialog from 'primevue/dynamicdialog';
import InputText from 'primevue/inputtext';
import Listbox from 'primevue/listbox';
import Panel from 'primevue/panel';
import Password from 'primevue/password';
import SelectButton from 'primevue/selectbutton';
import Splitter from 'primevue/splitter';
import SplitterPanel from 'primevue/splitterpanel';
import TabView from 'primevue/tabview';
import TabPanel from 'primevue/tabpanel';
import Textarea from 'primevue/textarea';
import Toast from 'primevue/toast';
import Toolbar from 'primevue/toolbar';
import api from './api'

const app = createApp(App)
app.provide('$api', api)
app.use(PrimeVue)
app.use(createPinia())
app.use(ToastService)
app.use(DialogService)
app.use(ConfirmationService)
app.component('Button', Button)
app.component('Card', Card)
app.component('Checkbox', Checkbox)
app.component('ConfirmDialog', ConfirmDialog)
app.component('DynamicDialog', DynamicDialog)
app.component('InputText', InputText)
app.component('Listbox', Listbox)
app.component('Panel', Panel)
app.component('Password', Password)
app.component('SelectButton', SelectButton)
app.component('Splitter', Splitter)
app.component('SplitterPanel', SplitterPanel)
app.component('TabView', TabView)
app.component('TabPanel', TabPanel)
app.component('Textarea', Textarea)
app.component('Toast', Toast)
app.component('Toolbar', Toolbar)
app.mount('#app')
