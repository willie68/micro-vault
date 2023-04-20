<script setup>
import { useToast } from "primevue/usetoast";
import sapi from '../api'

const toast = useToast();

const onAdvancedUpload = () => {
};

const customBase64Uploader = async (event) => {
    const file = event.files[0];
    const reader = new FileReader();
    reader.readAsBinaryString(file);
    reader.onloadend = function () {
        const data = reader.result;
        let pclient = sapi.splaybook.upload(data)
        pclient.then(() => {
            toast.add({ severity: "success", summary: 'playbook uploaded', life: 3000 });
        })
    };
};
</script>

<template>
    <div class="grid">
        <div class="col-8 justify-content-left">
            <Panel header="Playbook upload">
                <FileUpload name="demo[]" url="api/v1/admin/playbook" @upload="onAdvancedUpload($event)" :multiple="true"
                    accept="application/json" :maxFileSize="1000000" customUpload @uploader="customBase64Uploader">
                    <template #empty>
                        <div class="flex align-items-center justify-content-center flex-column">
                            <i class="pi pi-cloud-upload border-2 border-circle p-5 text-8xl text-400 border-400" />
                            <p class="mt-4 mb-0">Drag and drop files to here to upload.</p>
                        </div>
                    </template>
                </FileUpload>
            </Panel>
        </div>
    </div>
</template>

<style scoped></style>