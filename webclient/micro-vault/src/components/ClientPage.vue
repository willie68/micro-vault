<script setup>
import { useToast } from "primevue/usetoast";
import { ref } from "vue";
import sapi from '../api'

const toast = useToast();
const selectedClient = ref();
const clients = ref([])

async function getClients() {
    let pclients = sapi.sclient.list()
    pclients.then((data) => {
        toast.add({ severity: "success", summary: 'clients', detail: data, life: 3000 });
        console.log(data)
        data.forEach((g) => {
            clients.value.push(g)
        })
        selectedClient.value = clients.value[0]
    })
}

getClients()

</script>

<template>
    <div class="grid">
        <div class="col-2 justify-content-left">
            <h3>Clients</h3>
            <Listbox v-model="selectedClient" :options="clients" optionLabel="name" class="w-full md:w-14rem"
                listStyle="max-height:250px; min-height:60vh" />
        </div>
        <div class="col-10 justify-content-left" v-if="selectedClient">
            <h3>Client properties</h3>
            <div class="grid">
                <div class="col-1">Name</div>
                <div class="col-4"><InputText style="width:100vh" v-model="selectedClient.name" disabled /></div>
            </div>
            <div class="grid">
                <div class="col-1">Access-Key</div>
                <div class="col-4"><InputText style="width:100vh" v-model="selectedClient.accesskey" disabled /></div>
            </div>
            <div class="grid">
                <div class="col-1">Secret</div>
                <div class="col-4"><InputText style="width:100vh" v-model="selectedClient.secret" disabled placeholder="*****"/></div>
            </div>
            <div class="grid">
                <div class="col-1">Groups</div>
                <div class="col-4"><Listbox style="width:100vh" :options="selectedClient.groups" /></div>
            </div>
        </div>
    </div>
</template>

<style scoped></style>