import { createApp } from 'vue'
import PrimeVue from 'primevue/config';
import { createPinia } from 'pinia'
import App from './App.vue'

import './assets/main.css'
import "primevue/resources/themes/vela-blue/theme.css";
import "primevue/resources/primevue.min.css";
import "primeicons/primeicons.css";
import "primeflex/primeflex.css";
import InputText from 'primevue/inputtext';
import Password from 'primevue/password';


const app = createApp(App)
app.use(PrimeVue);
app.use(createPinia())
app.component('InputText', InputText)
app.component('Password', Password)
app.mount('#app')
