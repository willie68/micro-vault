<script setup>
import { useToast } from "primevue/usetoast";
import { ref } from "vue";
import sapi from '../api'

const toast = useToast();
const selectedClient = ref();
const clients = ref([])
const lclients = ref(false)

const getClients = () => {
    lclients.value = true
    let pclients = sapi.sclient.list()
    pclients.then((data) => {
        clients.value = []
        data.forEach((g) => {
            clients.value.push(g)
        })
        selectedClient.value = clients.value[0]
        lclients.value = false
    })
}

getClients()

const addClient = () => {
    toast.add({ severity: "success", summary: "new client", life: 3000 })
}
</script>

<template>
    <div class="grid">
        <div class="col-2 justify-content-left">
            <Panel header="Clients">
                <template #icons>
                    <Button icon="pi pi-plus" aria-label="Add Client" text @click="addClient" />
                    <Button icon="pi pi-refresh" aria-label="Submit" :loading="lclients" text @click="getClients()" />
                </template>
                <Listbox v-model="selectedClient" :options="clients" optionLabel="name" class="m-0"
                    listStyle="max-height:60vh; min-height:60vh" emptyMessage="no clients available"/>
            </Panel>
        </div>
        <div class="col-10 justify-content-left" v-if="selectedClient">
            <Panel header="Client properties">
                <div class="p-pad-8">
                    <div class="grid">
                        <div class="col-1">Name</div>
                        <div class="col-4">
                            <InputText style="width:100vh" v-model="selectedClient.name" disabled />
                        </div>
                    </div>
                    <div class="grid">
                        <div class="col-1">Access-Key</div>
                        <div class="col-4">
                            <InputText style="width:100vh" v-model="selectedClient.accesskey" disabled />
                        </div>
                    </div>
                    <div class="grid">
                        <div class="col-1">Secret</div>
                        <div class="col-4">
                            <InputText style="width:100vh" v-model="selectedClient.secret" disabled placeholder="*****" />
                        </div>
                    </div>
                    <div class="grid">
                        <div class="col-1">Groups</div>
                        <div class="col-4">
                            <Listbox style="width:100vh" :options="selectedClient.groups" />
                        </div>
                    </div>
                </div>
            </Panel>
        </div>
    </div>
</template>

<style scoped></style>