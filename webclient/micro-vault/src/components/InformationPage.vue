<script setup>

const openCert = () => {
    window.open("/ca/cacert", "_blank")
};
</script>

<template>
    <div class="grid">
        <div class="col-8 justify-content-left">
            <Panel header="MV Certification Authority">
                <Button label="Root Certificate" link @click="openCert"/>
            </Panel>
        </div>
    </div>
</template>

<style scoped></style>