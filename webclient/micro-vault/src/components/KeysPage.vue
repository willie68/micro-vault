<script setup>
import { useToast } from "primevue/usetoast";
import { ref, watch } from 'vue'
import sapi from '../api'

const toast = useToast();
const selectedKey = ref()
const keys = ref([])
const group = ref()

async function getKeys() {
    let pkeys = sapi.skey.list()
    pkeys.then((data) => {
        toast.add({ severity: "success", summary: 'keys', detail: data, life: 3000 });
        console.log(data)
        keys.value = []
        data.forEach((g) => {
            keys.value.push(g)
        })
        selectedKey.value = keys.value[0]
    })
}

async function getFilteredKeys() {
    let pkeys = sapi.skey.filter(group.value)
    pkeys.then((data) => {
        toast.add({ severity: "success", summary: 'keys', detail: data, life: 3000 });
        console.log(data)
        keys.value = []
        data.forEach((g) => {
            keys.value.push(g)
        })
        selectedKey.value = keys.value[0]
    })
}

getKeys()

watch(group, (group, prevGroup) => {
    if (group) {
        getFilteredKeys()
    } else {
        getKeys()
    }
})


</script>

<template>
    <div class="grid">
        <div class="col-fixed justify-content-left" style="width: 240px">
            <h3>Keys</h3>
            <span class="p-input-icon-left">
                <i class="pi pi-search" />
                <InputText v-model="group" placeholder="Groupname" style="width:14rem"/>
            </span>
            <Listbox v-model="selectedKey" :options="keys" optionLabel="kid" class="w-full md:w-14rem"
                listStyle="max-height:250px; min-height:60vh" />
        </div>
        <div class="col-8 justify-content-left" v-if="selectedKey">
            <h3>Key properties</h3>
            <div class="grid">
                <div class="col-1">Alg</div>
                <div class="col-4">
                    <InputText style="width:100vh" v-model="selectedKey.alg" disabled />
                </div>
            </div>
            <div class="grid">
                <div class="col-1">ID</div>
                <div class="col-4">
                    <InputText style="width:100vh" v-model="selectedKey.kid" disabled />
                </div>
            </div>
            <div class="grid">
                <div class="col-1">Group</div>
                <div class="col-4">
                    <InputText style="width:100vh" v-model="selectedKey.group" disabled />
                </div>
            </div>
            <div class="grid">
                <div class="col-1">Created</div>
                <div class="col-4">
                    <InputText style="width:100vh" v-model="selectedKey.created" disabled />
                </div>
            </div>
            <div class="grid">
                <div class="col-1">Key</div>
                <div class="col-4">
                    <Textarea style="width:100vh" v-model="selectedKey.key" rows="5" disabled />
                </div>
            </div>
        </div>
    </div>
</template>

<style scoped></style>