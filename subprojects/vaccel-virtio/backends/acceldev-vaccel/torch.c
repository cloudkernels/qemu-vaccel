// SPDX-License-Identifier: Apache-2.0

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"

#include "torch.h"
#include "vaccel-virtio-common/core.h"
#include "vaccel-virtio-common/pack/torch.h"
#include <vaccel.h>

int vaccel_virtio_torch_model_load(struct vaccel_session *sess,
                                   struct vaccel_arg_array *read_args,
                                   struct vaccel_arg_array *write_args,
                                   Error **errp)
{
    if (!sess || !read_args || read_args->count < 1)
        return VACCEL_EINVAL;

    vaccel_id_t model_id;
    int ret = vaccel_arg_array_get_int64(read_args, &model_id);
    if (ret) {
        error_setg(errp, "Failed to unpack model.id arg");
        return ret;
    }

    struct vaccel_resource *model;
    ret = vaccel_resource_get_by_id(&model, model_id);
    if (ret) {
        error_setg(errp, "Unknown resource %" PRId64, model_id);
        return ret;
    }

    return vaccel_torch_model_load(sess, model);
}

int vaccel_virtio_torch_model_run(struct vaccel_session *sess,
                                  struct vaccel_arg_array *read_args,
                                  struct vaccel_arg_array *write_args,
                                  Error **errp)
{
    if (!sess || !read_args || read_args->count < 3 || !write_args ||
        write_args->count < 1)
        return VACCEL_EINVAL;

    vaccel_id_t model_id;
    int ret = vaccel_arg_array_get_int64(read_args, &model_id);
    if (ret) {
        error_setg(errp, "Failed to unpack model.id arg");
        return ret;
    }

    uint32_t u_nr_inputs;
    ret = vaccel_arg_array_get_uint32(read_args, &u_nr_inputs);
    if (ret) {
        error_setg(errp, "Failed to unpack nr_inputs arg");
        return ret;
    }
    size_t nr_inputs = u_nr_inputs;

    if (nr_inputs < 1) {
        error_setg(errp, "Expected at least 1 input");
        return VACCEL_EINVAL;
    }

    uint32_t u_nr_outputs;
    ret = vaccel_arg_array_get_uint32(read_args, &u_nr_outputs);
    if (ret) {
        error_setg(errp, "Failed to unpack nr_outputs arg");
        return ret;
    }
    size_t nr_outputs = u_nr_outputs;

    struct vaccel_torch_tensor **inputs =
        malloc(nr_inputs * sizeof(struct vaccel_torch_tensor *));
    if (!inputs)
        return VACCEL_ENOMEM;

    struct vaccel_torch_tensor **outputs =
        malloc(nr_outputs * sizeof(struct vaccel_torch_tensor *));
    if (!outputs) {
        ret = VACCEL_ENOMEM;
        goto release_inputs;
    }

    for (size_t i = 0; i < nr_inputs; i++)
        inputs[i] = NULL;

    ret = vaccel_virtio_unpack_torch_tensors(read_args, inputs, nr_inputs);
    if (ret) {
        error_setg(errp, "Failed to unpack inputs");
        goto release_outputs;
    }

    struct vaccel_torch_buffer *run_options = NULL;
    void *data;
    size_t data_size;
    ret = vaccel_arg_array_get_buffer(read_args, &data, &data_size);
    if (!ret) {
        ret = vaccel_torch_buffer_new(&run_options, data, data_size);
        if (ret) {
            error_setg(errp, "Could not create run_options");
            goto release_outputs;
        }
    } else if (ret != VACCEL_ERANGE) {
        error_setg(errp, "Failed to unpack run_options arg");
        goto release_outputs;
    }

    struct vaccel_resource *model;
    ret = vaccel_resource_get_by_id(&model, model_id);
    if (ret) {
        error_setg(errp, "Unknown resource %" PRId64, model_id);
        goto release_run_options;
    }

    ret = vaccel_torch_model_run(sess, model, run_options, inputs, nr_inputs,
                                 outputs, nr_outputs);
    if (ret)
        goto release_run_options;

    // Overwrite write args
    vaccel_arg_array_clear(write_args);

    // FIXME: verify buffers fit

    ret = vaccel_virtio_pack_torch_tensors(write_args, outputs, nr_outputs);
    if (ret)
        error_setg(errp, "Failed to pack outputs");

    // FIXME: correct freeing
    for (size_t i = 0; i < nr_outputs; i++) {
        if (!outputs[i])
            continue;
        if (ret) {
            if (vaccel_torch_tensor_delete(outputs[i]))
                warn_report("Could not delete outputs[%zu]", i);
        } else {
            // Manually free output tensors, to avoid invalidating
            // dims/data
            free(outputs[i]);
        }
    }

release_run_options:
    if (run_options) {
        void *_bdata;
        size_t _bsize;
        vaccel_torch_buffer_take_data(run_options, &_bdata, &_bsize);
        if (vaccel_torch_buffer_delete(run_options))
            warn_report("Could not delete run_options");
    }
release_outputs:
    free(outputs);
release_inputs:
    for (size_t i = 0; i < nr_inputs; i++)
        if (inputs[i] && vaccel_torch_tensor_delete(inputs[i]))
            warn_report("Could not delete inputs[%zu]", i);
    free(inputs);

    return ret;
}
