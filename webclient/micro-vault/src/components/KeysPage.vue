<script setup>
import { useToast } from "primevue/usetoast";
import { ref, watch } from 'vue'
import sapi from '../api'

const toast = useToast();
const selectedKey = ref()
const keys = ref([])
const group = ref()
const lkeys = ref(false)

async function getKeys() {
    lkeys.value = true
    let pkeys = sapi.skey.list()
    pkeys.then((data) => {
        keys.value = []
        data.forEach((g) => {
            keys.value.push(g)
        })
        selectedKey.value = keys.value[0]
        lkeys.value = false
    })
}

async function getFilteredKeys() {
    let pkeys = sapi.skey.filter(group.value)
    pkeys.then((data) => {
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
            <Panel header="Keys">
                <template #icons>
                    <Button icon="pi pi-plus" aria-label="Add Group" text @click="addKey" />
                    <Button icon="pi pi-refresh" aria-label="Refresh" :loading="lkeys" text @click="getKeys" />
                </template>
                <span class="p-input-icon-left">
                    <i class="pi pi-search" />
                    <InputText name="groupfilter" id="groupfilter" v-model="group" placeholder="Groupname" style="width:14rem" />
                </span>
                <Listbox v-model="selectedKey" :options="keys" optionLabel="kid" class="w-full md:w-14rem"
                    listStyle="max-height:60vh; min-height:60vh" emptyMessage="no keys available"/>
            </Panel>
        </div>
        <div class="col-8 justify-content-left" v-if="selectedKey">
            <Panel header="Key properties">
                <div class="p-pad-8">
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
            </Panel>
        </div>
    </div>
</template>

<style scoped></style>