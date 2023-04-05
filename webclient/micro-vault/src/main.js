import { createApp } from 'vue'
import PrimeVue from 'primevue/config';
import { createPinia } from 'pinia'
import App from './App.vue'

import './assets/main.css'
import "primevue/resources/themes/vela-blue/theme.css";
import "primevue/resources/primevue.min.css";
import "primeicons/primeicons.css";
import "primeflex/primeflex.css";
import Button from 'primevue/button';
import Card from 'primevue/card';
import InputText from 'primevue/inputtext';
import Panel from 'primevue/panel';
import Password from 'primevue/password';
import Splitter from 'primevue/splitter';
import SplitterPanel from 'primevue/splitterpanel';
import TabView from 'primevue/tabview';
import TabPanel from 'primevue/tabpanel';

const app = createApp(App)
app.use(PrimeVue);
app.use(createPinia())
app.component('Button', Button)
app.component('Card', Card)
app.component('InputText', InputText)
app.component('Panel', Panel)
app.component('Password', Password)
app.component('Splitter', Splitter)
app.component('SplitterPanel', SplitterPanel)
app.component('TabView', TabView)
app.component('TabPanel', TabPanel)
app.mount('#app')
