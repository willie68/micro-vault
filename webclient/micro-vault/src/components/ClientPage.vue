<script setup>
import { useToast } from "primevue/usetoast";
import { useConfirm } from "primevue/useconfirm";

import { ref } from "vue";
import sapi from '../api'

const toast = useToast();
const confirm = useConfirm();

const selectedClient = ref();
const tempClient = ref({ mname: "", accesskey: "", secret: "", crt: {} });
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
            if (g.crt == null) {
                g.crt = {}
            }
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
    selectedClient.value = { name: "", groups: [], crt: {} }
    lnew.value = true
    ledit.value = true
}

const cancelClient = () => {
    ledit.value = false
    lnew.value = false
    selectedClient.value = tempClient.value
}

const editClient = () => {
    tempClient.value = selectedClient.value
    lnew.value = false
    ledit.value = true
}

const saveClient = () => {
    if (lnew.value) {
        // creating a new client
        let pclient = sapi.sclient.new(selectedClient.value)
        pclient.then((data) => {
            let message = 'new client with name "' + data.name + "\" created. Please copy the access key and the secret from this view. The secret is only shown once."
            toast.add({ severity: "success", summary: 'new client', detail: message, life: 10000 });
            console.log(data)
            selectedClient.value = data
            getClients()
        })
    } else {
        // saving the changes
        toast.add({ severity: "success", summary: 'save client', life: 3000 });
        let pclient = sapi.sclient.edit(selectedClient.value)
        pclient.then((data) => {
            let message = 'client with name "' + data.name + "\" saved."
            toast.add({ severity: "success", summary: 'new client', detail: message, life: 10000 });
            console.log(data)
            selectedClient.value = data
        })
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
            <Panel>
                <template #header>
                    Client properties: <strong>{{ selectedClient.name }}</strong>
                </template>
                <template #icons>
                    <Button text disabled label="|" />
                    <Button icon="pi pi-pencil" aria-label="Edit Client" text @click="editClient" :disabled="ledit"
                        v-tooltip.left="'Edit the selected client'"></Button>
                    <Button icon="pi pi-trash" aria-label="Delete Client" text @click="deleteClient" :disabled="ledit"
                        v-tooltip.left="'Delete the selected client'"></Button>
                    <Button icon="pi pi-save" aria-label="Save Client" text @click="saveClient" :disabled="!ledit"
                        v-tooltip.left="'Save the client'"></Button>
                    <Button icon="pi pi-times" aria-label="Cancel Client" text @click="cancelClient" :disabled="!ledit"
                        v-tooltip.left="'Cancel the editing'"></Button>
                </template>
                <TabView>
                    <TabPanel header="General">
                        <div class="p-pad-8">
                            <div class="grid">
                                <div class="col-1">Name</div>
                                <div class="col-5">
                                    <InputText id="name" v-model="selectedClient.name" :readonly="!lnew" />
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
                                    <InputText id="secret" v-model="selectedClient.secret" readonly placeholder="*****" />
                                </div>
                            </div>
                            <div class="grid">
                                <div class="col-1">Groups</div>
                                <div class="col-4">
                                    <Chips id="groups" v-model="selectedClient.groups" :disabled="!ledit" />
                                </div>
                            </div>
                        </div>
                    </TabPanel>
                    <TabPanel header="Certificate Request">
                        <div class="p-pad-8">
                            <div class="grid">
                                <div class="col-1">Common Name</div>
                                <div class="col-5">
                                    <InputText id="ucn" v-model="selectedClient.crt.ucn" :readonly="!ledit" />
                                </div>
                                <div class="col-1">Country</div>
                                <div class="col-5">
                                    <InputText id="uco" v-model="selectedClient.crt.uco" :readonly="!ledit" />
                                </div>
                            </div>
                            <div class="grid">
                                <div class="col-1">Province</div>
                                <div class="col-5">
                                    <InputText id="upr" v-model="selectedClient.crt.upr" :readonly="!ledit" />
                                </div>
                                <div class="col-1">Locality</div>
                                <div class="col-5">
                                    <InputText id="ulo" v-model="selectedClient.crt.ulo" :readonly="!ledit" />
                                </div>
                            </div>
                            <div class="grid">
                                <div class="col-1">Organisation</div>
                                <div class="col-5">
                                    <InputText id="uor" v-model="selectedClient.crt.uor" :readonly="!ledit" />
                                </div>
                                <div class="col-1">Organisation Unit</div>
                                <div class="col-5">
                                    <InputText id="uou" v-model="selectedClient.crt.uou" :readonly="!ledit" />
                                </div>
                            </div>
                            <div class="grid">
                                <div class="col-1">Street Address</div>
                                <div class="col-5">
                                    <InputText id="usa" v-model="selectedClient.crt.usa" :readonly="!ledit" />
                                </div>
                                <div class="col-1">Postal Code</div>
                                <div class="col-5">
                                    <InputText id="upc" v-model="selectedClient.crt.upc" :readonly="!ledit" />
                                </div>
                            </div>
                            <div class="grid">
                                <div class="col-1">EMail</div>
                                <div class="col-5">
                                    <InputText id="uem" v-model="selectedClient.crt.uem" :readonly="!ledit" />
                                </div>
                            </div>
                            <div class="grid">
                                <div class="col-1">DNS Names</div>
                                <div class="col-9">
                                    <Chips id="dns" v-model="selectedClient.crt.dns" :disabled="!ledit" />
                                </div>
                            </div>
                            <div class="grid">
                                <div class="col-1">IPs</div>
                                <div class="col-9">
                                    <Chips id="groups" v-model="selectedClient.crt.ip" :disabled="!ledit" />
                                </div>
                            </div>
                            <div class="grid">
                                <div class="col-1">URIs</div>
                                <div class="col-9">
                                    <Chips id="groups" v-model="selectedClient.crt.uri" :disabled="!ledit" />
                                </div>
                            </div>
                            <div class="grid">
                                <div class="col-1">period of validity</div>
                                <div class="col-5">
                                    <InputText id="vad" v-model="selectedClient.crt.vad" :readonly="!ledit" v-tooltip.right="'insert a duration like 3w4d7h (3 weeks, 4 days and 7 hours)'"/>
                                </div>
                            </div>
                        </div>
                    </TabPanel>
                </TabView>
            </Panel>
        </div>
    </div>
</template>

<style scoped></style>