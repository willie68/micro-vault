<script setup>
import { useToast } from "primevue/usetoast";
import { useConfirm } from "primevue/useconfirm";

import { ref } from "vue";
import sapi from '../api'

const toast = useToast();
const confirm = useConfirm();

const selectedClient = ref();
const tempClient = ref({ mname: "", accesskey: "", secret: "" });
const clients = ref([])
const lclients = ref(false)
const ledit = ref(false)
const lnew = ref(false)

const getClients = () => {
    lclients.value = true
    let pclients = sapi.sclient.list()
    pclients.then((data) => {
        clients.value = []
        data.forEach((g) => {
            clients.value.push(g)
        })
        if (!selectedClient.value) {
            selectedClient.value = clients.value[0]
        }
        lclients.value = false
    })
}

getClients()

const addClient = () => {
    tempClient.value = selectedClient.value
    selectedClient.value = { name: "", groups: [] }
    lnew.value = true
    ledit.value = true
}

const cancelClient = () => {
    ledit.value = false
    lnew.value = false
    selectedClient.value = tempClient.value
}

const saveClient = () => {
    if (lnew.value) {
        // creating a new client
        let pclient = sapi.sclient.new(selectedClient.value)
        pclient.then((data) => {
            let message = 'new client with name \"' + data.name + "\" created. Please copy the access key and the secret from this view. The secret is only shown once."
            toast.add({ severity: "success", summary: 'new client', detail: message, life: 10000 });
            console.log(data)
            selectedClient.value = data
            getClients()
        })
    } else {
        // saving the changes
        toast.add({ severity: "success", summary: 'save client', life: 3000 });
    }

    ledit.value = false
    lnew.value = false
}

const deleteClient = () => {
    let clname = selectedClient.value.name
    confirm.require({
        message: 'Do you want to delete this client?',
        header: 'Delete Confirmation',
        icon: 'pi pi-info-circle',
        acceptClass: 'p-button-danger',
        accept: () => {
            console.log("delete client: " + clname)
            let pgroups = sapi.sclient.delete(clname)
            pgroups.then(() => {
                toast.add({ severity: "success", summary: 'client deleted', life: 3000 });
                getClients()
            })
        },
        reject: () => {
        }
    });
}
const copyAK = () => {
    navigator.clipboard.writeText(selectedClient.value.accesskey)
}
const copySK = () => {
    navigator.clipboard.writeText(selectedClient.value.secret)
}
</script>

<template>
    <div class="grid">
        <div class="col-2 justify-content-left">
            <Panel header="Clients">
                <template #icons>
                    <Button icon="pi pi-plus" aria-label="Add Client" text @click="addClient"
                        v-tooltip="'Create a new client'" />
                    <Button icon="pi pi-refresh" aria-label="Submit" :loading="lclients" text @click="getClients()" />
                </template>
                <Listbox v-model="selectedClient" :options="clients" optionLabel="name" class="m-0"
                    listStyle="max-height:60vh; min-height:60vh" emptyMessage="no clients available" />
            </Panel>
        </div>
        <div class="col-10 justify-content-left" v-if="selectedClient">
            <Panel header="Client properties">
                <template #icons>
                    <Button text disabled label="|" />
                    <Button icon="pi pi-trash" aria-label="Delete Client" text @click="deleteClient" :disabled="ledit"
                        v-tooltip.left="'Delete the selected client'"></Button>
                    <Button icon="pi pi-save" aria-label="Save Client" text @click="saveClient" :disabled="!ledit"
                        v-tooltip.left="'Save the client'"></Button>
                    <Button icon="pi pi-times" aria-label="Cancel Client" text @click="cancelClient" :disabled="!ledit"
                        v-tooltip.left="'Cancel the editing'"></Button>
                </template>
                <div class="p-pad-8">
                    <div class="grid">
                        <div class="col-1">Name</div>
                        <div class="col-5">
                            <InputText id="name" v-model="selectedClient.name" :readonly="!ledit" />
                        </div>
                    </div>
                    <div class="grid">
                        <div class="col-1">AccessKey</div>
                        <div class="col-5">
                            <InputText id="accesskey" v-model="selectedClient.accesskey" readonly />
                        </div>
                    </div>
                    <div class="grid">
                        <div class="col-1">Secret</div>
                        <div class="col-5">
                            <InputText id="secret" v-model="selectedClient.secret" readonly
                                placeholder="*****" />
                        </div>
                    </div>
                    <div class="grid">
                        <div class="col-1">Groups</div>
                        <div class="col-4">
                            <Chips id="groups" v-model="selectedClient.groups" />
                        </div>
                    </div>
                    <div class="grid">
                        <div class="col-1">Groups</div>
                        <div class="col-4">
                            <Listbox :options="selectedClient.groups" emptyMessage="no groups available"
                                readonly />
                        </div>
                    </div>
                </div>
            </Panel>
            <Toolbar />
        </div>
    </div>
</template>

<style scoped></style>