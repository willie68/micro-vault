<script setup>
import { useToast } from "primevue/usetoast";
import { ref, watch } from 'vue'
import sapi from '../api'

const toast = useToast();
const selectedGroup = ref()
const groups = ref([])
const clgroups = ref([])
const lgroups = ref(false)

async function getGroups() {
    lgroups.value = true
    let pgroups = sapi.sgroup.list()
    pgroups.then((data) => {
        toast.add({ severity: "success", summary: 'groups', detail: data, life: 3000 });
        console.log(data)
        groups.value = []
        data.forEach((g) => {
            groups.value.push(g)
        })
        selectedGroup.value = groups.value[0]
        lgroups.value = false
    })
}

async function getClients() {
    let pgroups = sapi.sclient.client4group(selectedGroup.value.name)
    pgroups.then((data) => {
        toast.add({ severity: "success", summary: 'clients', detail: data, life: 3000 });
        console.log(data)
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
    toast.add({ severity: "success", summary: "new group", life: 3000 })
}
</script>

<template>
    <div class="grid">
        <div class="col-fixed justify-content-left" style="width: 240px">
            <Panel header="Groups">
                <template #icons>
                    <Button icon="pi pi-plus" aria-label="Add Group" text @click="addGroup" />
                    <Button icon="pi pi-refresh" aria-label="Refresh" :loading="lgroups" text @click="getGroups()" />
                </template>
                <Listbox v-model="selectedGroup" :options="groups" optionLabel="name" class="m-0"
                    listStyle="max-height:60vh; min-height:60vh" />
            </Panel>
        </div>
        <div class="col-8 justify-content-left" v-if="selectedGroup">
            <h3>Group properties</h3>
            <div class="field grid">
                <label for="name" class="col-fixed" style="width: 100px">Name</label>
                <div class="col">
                    <InputText id="name" style="width:100vh" v-model="selectedGroup.name" disabled />
                </div>
            </div>
            <div class="field grid">
                <label for="isclient" class="col-fixed" style="width: 100px">is Client</label>
                <div class="col">
                    <Checkbox v-model="selectedGroup.isclient" :binary="true" disabled/>
                </div>
            </div>

            <div class="field grid" style="align-content: top;">
                <label for="labels" class="col-fixed" style="width: 100px;">Labels</label><br />
                <table id="labels">
                    <tr v-for="(value, key) in selectedGroup.label">
                        <td>{{ key }}</td>
                        <td>
                            <InputText v-model="selectedGroup.label[key]"></InputText>
                        </td>
                    </tr>
                </table>
            </div>
        </div>
        <div class="col-2 justify-content-left" v-if="selectedGroup">
            <h3>Clients in this group</h3>
            <Listbox :options="clgroups" optionLabel="name" class="w-full md:w-14rem"
                listStyle="max-height:250px; min-height:60vh" />
        </div>
    </div>
</template>

<style scoped></style>