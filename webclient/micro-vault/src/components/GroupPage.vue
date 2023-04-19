<script setup>
import { useDialog } from 'primevue/usedialog';
import { useToast } from "primevue/usetoast";
import { useConfirm } from "primevue/useconfirm";
import { ref, watch } from 'vue'
import sapi from '../api'
const dialog = useDialog();
const toast = useToast();
const confirm = useConfirm();

const selectedGroup = ref()
const tempSelectedGroup = ref()
const groups = ref([])
const clgroups = ref([])
const lgroups = ref(false)
const ledit = ref(false)

async function getGroups() {
    lgroups.value = true
    let pgroups = sapi.sgroup.list()
    pgroups.then((data) => {
        groups.value = []
        data.forEach((g) => {
            if (!g.isclient) {
                groups.value.push(g)
            }
        })
        selectedGroup.value = groups.value[0]
        lgroups.value = false
    })
}

async function getClients() {
    let pgroups = sapi.sclient.client4group(selectedGroup.value.name)
    pgroups.then((data) => {
        clgroups.value = []
        data.forEach((g) => {
            clgroups.value.push(g)
        })
    })
}

watch(selectedGroup, (selectedGroup, prevSelectedGroup) => {
    if (selectedGroup) {
        getClients()
    }
})

getGroups()

const addGroup = () => {
    tempSelectedGroup.value = selectedGroup.value
    selectedGroup.value = { name: "", isclient: false }
    ledit.value = true
}

const cancelGroup = () => {
    selectedGroup.value = tempSelectedGroup.value
    ledit.value = false
}

const saveGroup = () => {
    let pgroups = sapi.sgroup.store(selectedGroup.value)
    pgroups.then((data) => {
        toast.add({ severity: "success", summary: 'save group', detail: data, life: 3000 });
        console.log(data)
        getGroups()
    })
}

const deleteGroup = () => {
    confirm.require({
        message: 'Do you want to delete this group?',
        header: 'Delete Confirmation',
        icon: 'pi pi-info-circle',
        acceptClass: 'p-button-danger',
        accept: () => {
            let pgroups = sapi.sgroup.delete(selectedGroup.value.name)
            pgroups.then((data) => {
                toast.add({ severity: "success", summary: 'delete group', detail: data, life: 3000 });
                console.log(data)
                getGroups()
            })
        },
        reject: () => {
        }
    });
}

const createKey = () => {
    let pgkeys  = sapi.skey.createKey(selectedGroup.value.name)
    pgkeys.then((data) => {
        toast.add({ severity: "success", summary: 'key created', detail: "id:" + data.kid, life: 3000 });
        console.log(data)
    })
}
</script>

<template>
    <div class="grid">
        <div class="col-fixed justify-content-left" style="width: 240px">
            <Panel header="Groups">
                <template #icons>
                    <Button icon="pi pi-plus" aria-label="Add Group" text @click="addGroup" />
                    <Button icon="pi pi-refresh" aria-label="Refresh Groups" :loading="lgroups" text @click="getGroups" />
                </template>
                <Listbox v-model="selectedGroup" :options="groups" optionLabel="name" class="m-0"
                    listStyle="max-height:60vh; min-height:60vh" emptyMessage="no groups available"/>
            </Panel>
        </div>
        <div class="col-8 justify-content-left" v-if="selectedGroup">
            <Panel header="Group properties">
                <template #icons>
                    <Button icon="pi pi-trash" aria-label="Delete Group" text @click="deleteGroup" :disabled="ledit"></Button>
                    <Button icon="pi pi-save" aria-label="Save Group" text @click="saveGroup" :disabled="!ledit"></Button>
                    <Button icon="pi pi-times" aria-label="Cancel Group" text @click="cancelGroup" :disabled="!ledit"></Button>
                </template>
                <div class="p-pad-8">
                    <div class="field grid">
                        <label for="name" class="col-fixed" style="width: 100px">Name</label>
                        <div class="col">
                            <InputText id="name" style="width:100vh" v-model="selectedGroup.name" :disabled="!ledit" />
                        </div>
                    </div>
                    <div class="field grid">
                        <label for="isclient" class="col-fixed" style="width: 100px">is Client</label>
                        <div class="col">
                            <Checkbox v-model="selectedGroup.isclient" :binary="true" disabled />
                        </div>
                    </div>

                    <div class="field grid" style="align-content: top;">
                        <label for="labels" class="col-fixed" style="width: 100px;">Labels</label><br />
                        <table id="labels">
                            <tr v-for="(value, key) in selectedGroup.label">
                                <td>{{ key }}</td>
                                <td>
                                    <InputText :id="key" v-model="selectedGroup.label[key]" />
                                </td>
                            </tr>
                        </table>
                    </div>
                </div>
            </Panel>
            <Toolbar>
                <template #start>
                    <Button icon="pi pi-plus" aria-label="new group key" @click="createKey" label="Create new group key"/>
                </template>
            </Toolbar>
        </div>
        <div class="col-2 justify-content-left" v-if="selectedGroup">
            <Panel header="Clients in this group">
                <Listbox :options="clgroups" optionLabel="name" class="m-0" 
                listStyle="max-height:60vh; min-height:60vh" emptyMessage="no clients available"/>
            </Panel>
        </div>
    </div>
</template>

<style scoped></style>