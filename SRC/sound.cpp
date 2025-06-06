// NGTAUDIO
#include "scriptmath/scriptmath3d.h"
#include <unordered_set>
#define NOMINMAX
#include "MemoryStream.h"
#include "ngt.h"
#include "obfuscate.h"
#include "Poco/Exception.h"
#include "Poco/Net/HTTPClientSession.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/StreamCopier.h"
#include "Poco/URI.h"
#include "scriptarray/scriptarray.h"
#include "sound.h"
#include <numeric>
#include <thread>
using namespace std;
#include "stb_vorbis.h"
#define MINIAUDIO_IMPLEMENTATION
#include "miniaudio.h"
#include <stdint.h> /* Required for uint32_t which is used by STEAMAUDIO_VERSION. That dependency needs to be removed from Steam Audio - use IPLuint32 or "unsigned int" instead! */
#include <algorithm>
#include "phonon.h" /* Steam Audio */
#include "pack.h"
#define FORMAT ma_format_f32 /* Must be floating point. */
int SAMPLE_RATE = 44100;
int CHANNELS = 2;
#include "fx/freeverb.h"
#define VERBLIB_IMPLEMENTATION
#include <map>
#include "fx/verblib.h"

#ifdef __cplusplus
extern "C"
{
#endif

	/*
	The reverb node has one input and one output.
	*/
	typedef struct
	{
		ma_node_config nodeConfig;
		ma_uint32 channels; /* The number of channels of the source, which will be the same as the output. Must be 1 or 2. */
		ma_uint32 sampleRate;
		float roomSize;
		float damping;
		float width;
		float wetVolume;
		float dryVolume;
		float mode;
	} ma_reverb_node_config;

	MA_API ma_reverb_node_config ma_reverb_node_config_init(ma_uint32 channels, ma_uint32 sampleRate);

	typedef struct
	{
		ma_node_base baseNode;
		verblib reverb;
	} ma_reverb_node;

	MA_API ma_result ma_reverb_node_init(ma_node_graph* pNodeGraph, const ma_reverb_node_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_reverb_node* pReverbNode);
	MA_API void ma_reverb_node_uninit(ma_reverb_node* pReverbNode, const ma_allocation_callbacks* pAllocationCallbacks);

#ifdef __cplusplus
}
#endif
MA_API ma_reverb_node_config ma_reverb_node_config_init(ma_uint32 channels, ma_uint32 sampleRate, float dry, float wet, float room_size)
{
	ma_reverb_node_config config;

	MA_ZERO_OBJECT(&config);
	config.nodeConfig = ma_node_config_init(); /* Input and output channels will be set in ma_reverb_node_init(). */
	config.channels = channels;
	config.channels = channels;
	config.sampleRate = sampleRate;
	config.roomSize = room_size;
	config.damping = verblib_initialdamp;
	config.width = verblib_initialwidth;
	config.wetVolume = wet;
	config.dryVolume = dry;
	config.mode = verblib_initialmode;

	return config;
}

static void ma_reverb_node_process_pcm_frames(ma_node* pNode, const float** ppFramesIn, ma_uint32* pFrameCountIn, float** ppFramesOut, ma_uint32* pFrameCountOut)
{
	ma_reverb_node* pReverbNode = (ma_reverb_node*)pNode;

	(void)pFrameCountIn;

	verblib_process(&pReverbNode->reverb, ppFramesIn[0], ppFramesOut[0], *pFrameCountOut);
}

static ma_node_vtable g_ma_reverb_node_vtable =
{
	ma_reverb_node_process_pcm_frames,
	NULL,
	1, /* 1 input channel. */
	1, /* 1 output channel. */
	MA_NODE_FLAG_CONTINUOUS_PROCESSING };

MA_API ma_result ma_reverb_node_init(ma_node_graph* pNodeGraph, const ma_reverb_node_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_reverb_node* pReverbNode)
{
	ma_result result;
	ma_node_config baseConfig;

	if (pReverbNode == NULL)
	{
		return MA_INVALID_ARGS;
	}

	MA_ZERO_OBJECT(pReverbNode);

	if (pConfig == NULL)
	{
		return MA_INVALID_ARGS;
	}

	if (verblib_initialize(&pReverbNode->reverb, (unsigned long)pConfig->sampleRate, (unsigned int)pConfig->channels) == 0)
	{
		return MA_INVALID_ARGS;
	}

	baseConfig = pConfig->nodeConfig;
	baseConfig.vtable = &g_ma_reverb_node_vtable;
	baseConfig.pInputChannels = &pConfig->channels;
	baseConfig.pOutputChannels = &pConfig->channels;

	result = ma_node_init(pNodeGraph, &baseConfig, pAllocationCallbacks, &pReverbNode->baseNode);
	if (result != MA_SUCCESS)
	{
		return result;
	}

	return MA_SUCCESS;
}

MA_API void ma_reverb_node_uninit(ma_reverb_node* pReverbNode, const ma_allocation_callbacks* pAllocationCallbacks)
{
	/* The base node is always uninitialized first. */
	ma_node_uninit(pReverbNode, pAllocationCallbacks);
}

/* Include ma_vocoder_node.h after miniaudio.h */
#define VOCLIB_IMPLEMENTATION
#include "fx/voclib.h"

#ifdef __cplusplus
extern "C"
{
#endif

	/*
	The vocoder node has two inputs and one output. Inputs:

		Input Bus 0: The source/carrier stream.
		Input Bus 1: The excite/modulator stream.

	The source (input bus 0) and output must have the same channel count, and is restricted to 1 or 2.
	The excite (input bus 1) is restricted to 1 channel.
	*/
	typedef struct
	{
		ma_node_config nodeConfig;
		ma_uint32 channels; /* The number of channels of the source, which will be the same as the output. Must be 1 or 2. The excite bus must always have one channel. */
		ma_uint32 sampleRate;
		ma_uint32 bands;		  /* Defaults to 16. */
		ma_uint32 filtersPerBand; /* Defaults to 6. */
	} ma_vocoder_node_config;

	MA_API ma_vocoder_node_config ma_vocoder_node_config_init(ma_uint32 channels, ma_uint32 sampleRate);

	typedef struct
	{
		ma_node_base baseNode;
		voclib_instance voclib;
	} ma_vocoder_node;

	MA_API ma_result ma_vocoder_node_init(ma_node_graph* pNodeGraph, const ma_vocoder_node_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_vocoder_node* pVocoderNode);
	MA_API void ma_vocoder_node_uninit(ma_vocoder_node* pVocoderNode, const ma_allocation_callbacks* pAllocationCallbacks);

#ifdef __cplusplus
}
#endif

MA_API ma_vocoder_node_config ma_vocoder_node_config_init(ma_uint32 channels, ma_uint32 sampleRate)
{
	ma_vocoder_node_config config;

	MA_ZERO_OBJECT(&config);
	config.nodeConfig = ma_node_config_init(); /* Input and output channels will be set in ma_vocoder_node_init(). */
	config.channels = channels;
	config.sampleRate = sampleRate;
	config.bands = 16;
	config.filtersPerBand = 6;

	return config;
}

static void ma_vocoder_node_process_pcm_frames(ma_node* pNode, const float** ppFramesIn, ma_uint32* pFrameCountIn, float** ppFramesOut, ma_uint32* pFrameCountOut)
{
	ma_vocoder_node* pVocoderNode = (ma_vocoder_node*)pNode;

	(void)pFrameCountIn;

	voclib_process(&pVocoderNode->voclib, ppFramesIn[0], ppFramesIn[1], ppFramesOut[0], *pFrameCountOut);
}

static ma_node_vtable g_ma_vocoder_node_vtable =
{
	ma_vocoder_node_process_pcm_frames,
	NULL,
	2, /* 2 input channels. */
	1, /* 1 output channel. */
	0 };

MA_API ma_result ma_vocoder_node_init(ma_node_graph* pNodeGraph, const ma_vocoder_node_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_vocoder_node* pVocoderNode)
{
	ma_result result;
	ma_node_config baseConfig;
	ma_uint32 inputChannels[2];
	ma_uint32 outputChannels[1];

	if (pVocoderNode == NULL)
	{
		return MA_INVALID_ARGS;
	}

	MA_ZERO_OBJECT(pVocoderNode);

	if (pConfig == NULL)
	{
		return MA_INVALID_ARGS;
	}

	if (voclib_initialize(&pVocoderNode->voclib, (unsigned char)pConfig->bands, (unsigned char)pConfig->filtersPerBand, (unsigned int)pConfig->sampleRate, (unsigned char)pConfig->channels) == 0)
	{
		return MA_INVALID_ARGS;
	}

	inputChannels[0] = pConfig->channels;  /* Source/carrier. */
	inputChannels[1] = 1;				   /* Excite/modulator. Must always be single channel. */
	outputChannels[0] = pConfig->channels; /* Output channels is always the same as the source/carrier. */

	baseConfig = pConfig->nodeConfig;
	baseConfig.vtable = &g_ma_vocoder_node_vtable;
	baseConfig.pInputChannels = inputChannels;
	baseConfig.pOutputChannels = outputChannels;

	result = ma_node_init(pNodeGraph, &baseConfig, pAllocationCallbacks, &pVocoderNode->baseNode);
	if (result != MA_SUCCESS)
	{
		return result;
	}

	return MA_SUCCESS;
}

MA_API void ma_vocoder_node_uninit(ma_vocoder_node* pVocoderNode, const ma_allocation_callbacks* pAllocationCallbacks)
{
	/* The base node must always be initialized first. */
	ma_node_uninit(pVocoderNode, pAllocationCallbacks);
}
#ifdef __cplusplus
extern "C"
{
#endif

	/*
	The trim node has one input and one output.
	*/
	typedef struct
	{
		ma_node_config nodeConfig;
		ma_uint32 channels;
		float threshold;
	} ma_ltrim_node_config;

	MA_API ma_ltrim_node_config ma_ltrim_node_config_init(ma_uint32 channels, float threshold);

	typedef struct
	{
		ma_node_base baseNode;
		float threshold;
		ma_bool32 foundStart;
	} ma_ltrim_node;

	MA_API ma_result ma_ltrim_node_init(ma_node_graph* pNodeGraph, const ma_ltrim_node_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_ltrim_node* pTrimNode);
	MA_API void ma_ltrim_node_uninit(ma_ltrim_node* pTrimNode, const ma_allocation_callbacks* pAllocationCallbacks);

#ifdef __cplusplus
}
#endif
MA_API ma_ltrim_node_config ma_ltrim_node_config_init(ma_uint32 channels, float threshold)
{
	ma_ltrim_node_config config;

	MA_ZERO_OBJECT(&config);
	config.nodeConfig = ma_node_config_init(); /* Input and output channels will be set in ma_ltrim_node_init(). */
	config.channels = channels;
	config.threshold = threshold;

	return config;
}

static void ma_ltrim_node_process_pcm_frames(ma_node* pNode, const float** ppFramesIn, ma_uint32* pFrameCountIn, float** ppFramesOut, ma_uint32* pFrameCountOut)
{
	ma_ltrim_node* pTrimNode = (ma_ltrim_node*)pNode;
	ma_uint32 framesProcessedIn = 0;
	ma_uint32 framesProcessedOut = 0;
	ma_uint32 channelCount = ma_node_get_input_channels(pNode, 0);

	/*
	If we haven't yet found the start, skip over every input sample until we find a frame outside
	of the threshold.
	*/
	if (pTrimNode->foundStart == MA_FALSE)
	{
		while (framesProcessedIn < *pFrameCountIn)
		{
			ma_uint32 iChannel = 0;
			for (iChannel = 0; iChannel < channelCount; iChannel += 1)
			{
				float sample = ppFramesIn[0][framesProcessedIn * channelCount + iChannel];
				if (sample < -pTrimNode->threshold || sample > pTrimNode->threshold)
				{
					pTrimNode->foundStart = MA_TRUE;
					break;
				}
			}

			if (pTrimNode->foundStart)
			{
				break; /* The start has been found. Get out of this loop and finish off processing. */
			}
			else
			{
				framesProcessedIn += 1;
			}
		}
	}

	/* If there's anything left, just copy it over. */
	framesProcessedOut = ma_min(*pFrameCountOut, *pFrameCountIn - framesProcessedIn);
	ma_copy_pcm_frames(ppFramesOut[0], &ppFramesIn[0][framesProcessedIn], framesProcessedOut, ma_format_f32, channelCount);

	framesProcessedIn += framesProcessedOut;

	/* We always "process" every input frame, but we may only done a partial output. */
	*pFrameCountIn = framesProcessedIn;
	*pFrameCountOut = framesProcessedOut;
}

static ma_node_vtable g_ma_ltrim_node_vtable =
{
	ma_ltrim_node_process_pcm_frames,
	NULL,
	1, /* 1 input channel. */
	1, /* 1 output channel. */
	MA_NODE_FLAG_DIFFERENT_PROCESSING_RATES };

MA_API ma_result ma_ltrim_node_init(ma_node_graph* pNodeGraph, const ma_ltrim_node_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_ltrim_node* pTrimNode)
{
	ma_result result;
	ma_node_config baseConfig;

	if (pTrimNode == NULL)
	{
		return MA_INVALID_ARGS;
	}

	MA_ZERO_OBJECT(pTrimNode);

	if (pConfig == NULL)
	{
		return MA_INVALID_ARGS;
	}

	pTrimNode->threshold = pConfig->threshold;
	pTrimNode->foundStart = MA_FALSE;

	baseConfig = pConfig->nodeConfig;
	baseConfig.vtable = &g_ma_ltrim_node_vtable;
	baseConfig.pInputChannels = &pConfig->channels;
	baseConfig.pOutputChannels = &pConfig->channels;

	result = ma_node_init(pNodeGraph, &baseConfig, pAllocationCallbacks, &pTrimNode->baseNode);
	if (result != MA_SUCCESS)
	{
		return result;
	}

	return MA_SUCCESS;
}

MA_API void ma_ltrim_node_uninit(ma_ltrim_node* pTrimNode, const ma_allocation_callbacks* pAllocationCallbacks)
{
	/* The base node is always uninitialized first. */
	ma_node_uninit(pTrimNode, pAllocationCallbacks);
}
#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct
	{
		ma_node_config nodeConfig;
		ma_uint32 channels;
	} ma_channel_combiner_node_config;

	MA_API ma_channel_combiner_node_config ma_channel_combiner_node_config_init(ma_uint32 channels);

	typedef struct
	{
		ma_node_base baseNode;
	} ma_channel_combiner_node;

	MA_API ma_result ma_channel_combiner_node_init(ma_node_graph* pNodeGraph, const ma_channel_combiner_node_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_channel_combiner_node* pSeparatorNode);
	MA_API void ma_channel_combiner_node_uninit(ma_channel_combiner_node* pSeparatorNode, const ma_allocation_callbacks* pAllocationCallbacks);

#ifdef __cplusplus
}
#endif
MA_API ma_channel_combiner_node_config ma_channel_combiner_node_config_init(ma_uint32 channels)
{
	ma_channel_combiner_node_config config;

	MA_ZERO_OBJECT(&config);
	config.nodeConfig = ma_node_config_init(); /* Input and output channels will be set in ma_channel_combiner_node_init(). */
	config.channels = channels;

	return config;
}

static void ma_channel_combiner_node_process_pcm_frames(ma_node* pNode, const float** ppFramesIn, ma_uint32* pFrameCountIn, float** ppFramesOut, ma_uint32* pFrameCountOut)
{
	ma_channel_combiner_node* pCombinerNode = (ma_channel_combiner_node*)pNode;

	(void)pFrameCountIn;

	ma_interleave_pcm_frames(ma_format_f32, ma_node_get_output_channels(pCombinerNode, 0), *pFrameCountOut, (const void**)ppFramesIn, (void*)ppFramesOut[0]);
}

static ma_node_vtable g_ma_channel_combiner_node_vtable =
{
	ma_channel_combiner_node_process_pcm_frames,
	NULL,
	MA_NODE_BUS_COUNT_UNKNOWN, /* Input bus count is determined by the channel count and is unknown until the node instance is initialized. */
	1,						   /* 1 output bus. */
	0						   /* Default flags. */
};

MA_API ma_result ma_channel_combiner_node_init(ma_node_graph* pNodeGraph, const ma_channel_combiner_node_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_channel_combiner_node* pCombinerNode)
{
	ma_result result;
	ma_node_config baseConfig;
	ma_uint32 inputChannels[MA_MAX_NODE_BUS_COUNT];
	ma_uint32 outputChannels[1];
	ma_uint32 iChannel;

	if (pCombinerNode == NULL)
	{
		return MA_INVALID_ARGS;
	}

	MA_ZERO_OBJECT(pCombinerNode);

	if (pConfig == NULL)
	{
		return MA_INVALID_ARGS;
	}

	/* All input channels are mono. */
	for (iChannel = 0; iChannel < pConfig->channels; iChannel += 1)
	{
		inputChannels[iChannel] = 1;
	}

	outputChannels[0] = pConfig->channels;

	baseConfig = pConfig->nodeConfig;
	baseConfig.vtable = &g_ma_channel_combiner_node_vtable;
	baseConfig.inputBusCount = pConfig->channels; /* The vtable has an unknown channel count, so must specify it here. */
	baseConfig.pInputChannels = inputChannels;
	baseConfig.pOutputChannels = outputChannels;

	result = ma_node_init(pNodeGraph, &baseConfig, pAllocationCallbacks, &pCombinerNode->baseNode);
	if (result != MA_SUCCESS)
	{
		return result;
	}

	return MA_SUCCESS;
}

MA_API void ma_channel_combiner_node_uninit(ma_channel_combiner_node* pCombinerNode, const ma_allocation_callbacks* pAllocationCallbacks)
{
	/* The base node is always uninitialized first. */
	ma_node_uninit(pCombinerNode, pAllocationCallbacks);
}
#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct
	{
		ma_node_config nodeConfig;
		ma_uint32 channels;
	} ma_channel_separator_node_config;

	MA_API ma_channel_separator_node_config ma_channel_separator_node_config_init(ma_uint32 channels);

	typedef struct
	{
		ma_node_base baseNode;
	} ma_channel_separator_node;

	MA_API ma_result ma_channel_separator_node_init(ma_node_graph* pNodeGraph, const ma_channel_separator_node_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_channel_separator_node* pSeparatorNode);
	MA_API void ma_channel_separator_node_uninit(ma_channel_separator_node* pSeparatorNode, const ma_allocation_callbacks* pAllocationCallbacks);

#ifdef __cplusplus
}
#endif
MA_API ma_channel_separator_node_config ma_channel_separator_node_config_init(ma_uint32 channels)
{
	ma_channel_separator_node_config config;

	MA_ZERO_OBJECT(&config);
	config.nodeConfig = ma_node_config_init(); /* Input and output channels will be set in ma_channel_separator_node_init(). */
	config.channels = channels;

	return config;
}

static void ma_channel_separator_node_process_pcm_frames(ma_node* pNode, const float** ppFramesIn, ma_uint32* pFrameCountIn, float** ppFramesOut, ma_uint32* pFrameCountOut)
{
	ma_channel_separator_node* pSplitterNode = (ma_channel_separator_node*)pNode;

	(void)pFrameCountIn;

	ma_deinterleave_pcm_frames(ma_format_f32, ma_node_get_input_channels(pSplitterNode, 0), *pFrameCountOut, (const void*)ppFramesIn[0], (void**)ppFramesOut);
}

static ma_node_vtable g_ma_channel_separator_node_vtable =
{
	ma_channel_separator_node_process_pcm_frames,
	NULL,
	1,						   /* 1 input bus. */
	MA_NODE_BUS_COUNT_UNKNOWN, /* Output bus count is determined by the channel count and is unknown until the node instance is initialized. */
	0						   /* Default flags. */
};

MA_API ma_result ma_channel_separator_node_init(ma_node_graph* pNodeGraph, const ma_channel_separator_node_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_channel_separator_node* pSeparatorNode)
{
	ma_result result;
	ma_node_config baseConfig;
	ma_uint32 inputChannels[1];
	ma_uint32 outputChannels[MA_MAX_NODE_BUS_COUNT];
	ma_uint32 iChannel;

	if (pSeparatorNode == NULL)
	{
		return MA_INVALID_ARGS;
	}

	MA_ZERO_OBJECT(pSeparatorNode);

	if (pConfig == NULL)
	{
		return MA_INVALID_ARGS;
	}

	if (pConfig->channels > MA_MAX_NODE_BUS_COUNT)
	{
		return MA_INVALID_ARGS; /* Channel count cannot exceed the maximum number of buses. */
	}

	inputChannels[0] = pConfig->channels;

	/* All output channels are mono. */
	for (iChannel = 0; iChannel < pConfig->channels; iChannel += 1)
	{
		outputChannels[iChannel] = 1;
	}

	baseConfig = pConfig->nodeConfig;
	baseConfig.vtable = &g_ma_channel_separator_node_vtable;
	baseConfig.outputBusCount = pConfig->channels; /* The vtable has an unknown channel count, so must specify it here. */
	baseConfig.pInputChannels = inputChannels;
	baseConfig.pOutputChannels = outputChannels;

	result = ma_node_init(pNodeGraph, &baseConfig, pAllocationCallbacks, &pSeparatorNode->baseNode);
	if (result != MA_SUCCESS)
	{
		return result;
	}

	return MA_SUCCESS;
}

MA_API void ma_channel_separator_node_uninit(ma_channel_separator_node* pSeparatorNode, const ma_allocation_callbacks* pAllocationCallbacks)
{
	/* The base node is always uninitialized first. */
	ma_node_uninit(pSeparatorNode, pAllocationCallbacks);
}

static IPLAudioSettings iplAudioSettings;
static IPLContextSettings iplContextSettings;
static IPLContext iplContext;
static IPLHRTFSettings iplHRTFSettings;
static IPLHRTF iplHRTF;
bool g_SoundInitialized = false;
class mixer;
static mixer* output = nullptr;
class sound;
class mixer {
public:
	ma_engine m_mixer;
	ma_engine_config m_config;
	mutable int ref = 0;
	std::unordered_set<mixer*> mixers;
	std::unordered_set<sound*> sounds;
	mixer* parent_mixer;
	ma_node* output_node; // Node to connect to parent mixer
	bool is_root = false;
	mixer(mixer* parent = nullptr, bool root = false) : parent_mixer(parent), is_root(root) {
		m_config = ma_engine_config_init();
		m_config.channels = CHANNELS;
		m_config.sampleRate = SAMPLE_RATE; // Default sample rate
		m_config.noDevice = MA_TRUE;
		if (ma_engine_init(&m_config, &m_mixer) != MA_SUCCESS) {
			throw std::runtime_error("Failed to initialize ma_engine in mixer");
		}
		output_node = ma_engine_get_endpoint(&m_mixer);
		if (parent)
		{
			set_mixer(parent);
		}
		else if (!root) {
			set_mixer(output);
		}
		ref = 1;
	}

	~mixer() {
		if (parent_mixer)
		{
			set_mixer(nullptr);
		}
		ma_engine_uninit(&m_mixer);
	}

	void AddRef() const
	{
		ref += 1;
	}
	void Release() const
	{
		if (--ref < 1)
		{
			delete this;
		}
	}

	void set_mixer(mixer* new_parent) {
		if (parent_mixer == new_parent)
			return;
		if (parent_mixer)
		{
			parent_mixer->mixers.erase(this);
			ma_node_detach_output_bus(output_node, 0);
		}
		parent_mixer = new_parent;
		if (parent_mixer)
		{
			parent_mixer->mixers.insert(this);
			ma_node_attach_output_bus(output_node, 0, parent_mixer->output_node, 0);
		}
	}

	inline ma_engine* get_engine() {
		return &m_mixer;
	}
};

static mixer* sound_default_mixer = nullptr;

static ma_device sound_mixer_device;
static asUINT period_size = 256;
static std::vector<float> g_OutputData;
static bool g_RecordOutput = false;
static void sound_mixer_device_callback(ma_device* pDevice, void* pOutput, const void* pInput, ma_uint32 frameCount)
{
	if (output)
		ma_engine_read_pcm_frames(&output->m_mixer, pOutput, frameCount, nullptr);
	if (g_RecordOutput) {
		const float* out = (const float*)pOutput;

		for (ma_uint32 i = 0; i < frameCount * 2; ++i) {
			g_OutputData.push_back(out[i]);
		}
	}
	(void)pInput;
}

struct AudioDevice
{
	std::string name;
	ma_device_id id;
};
static std::vector<AudioDevice> GetOutputAudioDevices()
{
	std::vector<AudioDevice> audioDevices;
	ma_result result;
	ma_context context;
	ma_device_info* pPlaybackDeviceInfos;
	ma_uint32 playbackDeviceCount;
	ma_uint32 iPlaybackDevice;

	if (ma_context_init(NULL, 0, NULL, &context) != MA_SUCCESS)
	{
		return audioDevices;
		;
	}

	result = ma_context_get_devices(&context, &pPlaybackDeviceInfos, &playbackDeviceCount, nullptr, nullptr);
	if (result != MA_SUCCESS)
	{
		return audioDevices;
	}
	for (iPlaybackDevice = 0; iPlaybackDevice < playbackDeviceCount; ++iPlaybackDevice)
	{
		const char* name = pPlaybackDeviceInfos[iPlaybackDevice].name;
		std::string name_str(name);
		AudioDevice ad;
		ad.id = pPlaybackDeviceInfos[iPlaybackDevice].id;
		ad.name = name;
		audioDevices.push_back(ad);
	}

	ma_context_uninit(&context);
	return audioDevices;
}
static std::vector<AudioDevice> GetInputAudioDevices()
{
	std::vector<AudioDevice> audioDevices;
	ma_result result;
	ma_context context;
	ma_device_info* pCaptureDeviceInfos;
	ma_uint32 captureDeviceCount;
	ma_uint32 iCaptureDevice;
	if (ma_context_init(NULL, 0, NULL, &context) != MA_SUCCESS) {
		return audioDevices;;
	}

	result = ma_context_get_devices(&context, nullptr, nullptr, &pCaptureDeviceInfos, &captureDeviceCount);
	if (result != MA_SUCCESS) {
		return audioDevices;
	}
	for (iCaptureDevice = 0; iCaptureDevice < captureDeviceCount; ++iCaptureDevice) {
		const char* name = pCaptureDeviceInfos[iCaptureDevice].name;
		AudioDevice ad;
		ad.id = pCaptureDeviceInfos[iCaptureDevice].id;
		ad.name = name;
		audioDevices.push_back(ad);
	}
	ma_context_uninit(&context);
	return audioDevices;
}

std::vector<AudioDevice> output_devs;
CScriptArray* get_output_audio_devices()
{
	if (!g_SoundInitialized)
		soundsystem_init();
	asIScriptContext* ctx = asGetActiveContext();
	asIScriptEngine* engine = ctx->GetEngine();
	asITypeInfo* arrayType = engine->GetTypeInfoById(engine->GetTypeIdByDecl("array<string>"));
	CScriptArray* array = CScriptArray::Create(arrayType, (asUINT)0);
	output_devs = GetOutputAudioDevices();
	if (output_devs.size() == 0)
		return array;
	array->Reserve(output_devs.size());
	for (asUINT i = 0; i < output_devs.size(); ++i)
	{
		array->InsertLast(&output_devs[i].name);
	}
	return array;
}

std::vector<AudioDevice> input_devs;
CScriptArray* get_input_audio_devices()
{
	if (!g_SoundInitialized)
		soundsystem_init();
	asIScriptContext* ctx = asGetActiveContext();
	asIScriptEngine* engine = ctx->GetEngine();
	asITypeInfo* arrayType = engine->GetTypeInfoById(engine->GetTypeIdByDecl("array<string>"));
	CScriptArray* array = CScriptArray::Create(arrayType, (asUINT)0);
	input_devs = GetInputAudioDevices();
	if (input_devs.size() == 0)
		return array;
	array->Reserve(input_devs.size());
	for (asUINT i = 0; i < input_devs.size(); ++i)
	{
		array->InsertLast(&input_devs[i].name);
	}
	return array;
}


static ma_device_id* g_InputDevice = nullptr;
bool set_output_audio_device(asUINT id)
{
	if (!g_SoundInitialized)
		soundsystem_init();
	if (output_devs.size() == 0)
		output_devs = GetOutputAudioDevices();
	ma_device_uninit(&sound_mixer_device);
	ma_device_config devConfig = ma_device_config_init(ma_device_type_playback);
	;
	devConfig.playback.pDeviceID = &output_devs[id].id;
	devConfig.periodSizeInFrames = period_size;
	devConfig.playback.channels = CHANNELS;
	devConfig.playback.format = FORMAT;
	devConfig.sampleRate = SAMPLE_RATE;
	devConfig.noClip = MA_TRUE;
	devConfig.dataCallback = sound_mixer_device_callback;
	if (ma_device_init(nullptr, &devConfig, &sound_mixer_device) != MA_SUCCESS)
		return false;
	ma_device_start(&sound_mixer_device);
	return true;
}


bool set_input_audio_device(asUINT id)
{
	if (!g_SoundInitialized)
		soundsystem_init();
	if (input_devs.size() == 0)
		input_devs = GetInputAudioDevices();
	g_InputDevice = &input_devs[id].id;
	return true;
}

static ma_result ma_result_from_IPLerror(IPLerror error)
{
	switch (error)
	{
	case IPL_STATUS_SUCCESS:
		return MA_SUCCESS;
	case IPL_STATUS_OUTOFMEMORY:
		return MA_OUT_OF_MEMORY;
	case IPL_STATUS_INITIALIZATION:
	case IPL_STATUS_FAILURE:
	default:
		return MA_ERROR;
	}
}

typedef struct
{
	ma_node_config nodeConfig;
	ma_uint32 channelsIn;
	IPLAudioSettings iplAudioSettings;
	IPLContext iplContext;
	IPLHRTF iplHRTF; /* There is one HRTF object to many binaural effect objects. */
} ma_steamaudio_binaural_node_config;

MA_API ma_steamaudio_binaural_node_config ma_steamaudio_binaural_node_config_init(ma_uint32 channelsIn, IPLAudioSettings iplAudioSettings, IPLContext iplContext, IPLHRTF iplHRTF);

typedef struct
{
	ma_node_base baseNode;
	IPLAudioSettings iplAudioSettings;
	IPLContext iplContext;
	IPLHRTF iplHRTF;
	IPLBinauralEffect iplEffect;
	ma_vec3f direction;
	float* ppBuffersIn[2];	/* Each buffer is an offset of _pHeap. */
	float* ppBuffersOut[2]; /* Each buffer is an offset of _pHeap. */
	void* _pHeap;
	ma_sound handle_;
} ma_steamaudio_binaural_node;

MA_API ma_result ma_steamaudio_binaural_node_init(ma_node_graph* pNodeGraph, const ma_steamaudio_binaural_node_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_steamaudio_binaural_node* pBinauralNode);
MA_API void ma_steamaudio_binaural_node_uninit(ma_steamaudio_binaural_node* pBinauralNode, const ma_allocation_callbacks* pAllocationCallbacks);
MA_API ma_result ma_steamaudio_binaural_node_set_direction(ma_steamaudio_binaural_node* pBinauralNode, float x, float y, float z);

MA_API ma_steamaudio_binaural_node_config ma_steamaudio_binaural_node_config_init(ma_uint32 channelsIn, IPLAudioSettings iplAudioSettings, IPLContext iplContext, IPLHRTF iplHRTF)
{
	ma_steamaudio_binaural_node_config config;

	MA_ZERO_OBJECT(&config);
	config.nodeConfig = ma_node_config_init();
	config.channelsIn = channelsIn;
	config.iplAudioSettings = iplAudioSettings;
	config.iplContext = iplContext;
	config.iplHRTF = iplHRTF;

	return config;
}

float spatial_blend_max_distance = 2.0f;
void set_spatial_blend_max_distance(float distance)
{
	spatial_blend_max_distance = distance;
}

float get_spatial_blend_max_distance()
{
	return spatial_blend_max_distance;
}

static void ma_steamaudio_binaural_node_process_pcm_frames(ma_node* pNode, const float** ppFramesIn, ma_uint32* pFrameCountIn, float** ppFramesOut, ma_uint32* pFrameCountOut)
{
	ma_steamaudio_binaural_node* pBinauralNode = (ma_steamaudio_binaural_node*)pNode;
	IPLBinauralEffectParams binauralParams;
	IPLAudioBuffer inputBufferDesc;
	IPLAudioBuffer outputBufferDesc;
	ma_uint32 totalFramesToProcess = *pFrameCountOut;
	ma_uint32 totalFramesProcessed = 0;
	binauralParams.direction.x = pBinauralNode->direction.x;
	binauralParams.direction.y = pBinauralNode->direction.z;
	binauralParams.direction.z = pBinauralNode->direction.y;
	ma_vec3f listener = ma_engine_listener_get_position(&output->m_mixer, ma_sound_get_listener_index(&pBinauralNode->handle_));
	float distance = sqrt((listener.x + binauralParams.direction.x) * (listener.x + binauralParams.direction.x) +
		(listener.y + binauralParams.direction.y) * (listener.y + binauralParams.direction.y) +
		(listener.z - binauralParams.direction.z) * (listener.z - binauralParams.direction.z));
	if (listener.x == binauralParams.direction.x && listener.y == binauralParams.direction.y && listener.z == binauralParams.direction.z)
	{
		binauralParams.interpolation = IPL_HRTFINTERPOLATION_NEAREST;
	}
	else
	{
		binauralParams.interpolation = IPL_HRTFINTERPOLATION_BILINEAR;
	}

	float normalizedDistance = distance / spatial_blend_max_distance;
	binauralParams.spatialBlend = min(0.0f + normalizedDistance, 1.0f);
	if (binauralParams.spatialBlend > 1.0f)
		binauralParams.spatialBlend = 1.0f;
	binauralParams.hrtf = pBinauralNode->iplHRTF;
	binauralParams.peakDelays = NULL;
	inputBufferDesc.numChannels = (IPLint32)ma_node_get_input_channels(pNode, 0);

	/* We'll run this in a loop just in case our deinterleaved buffers are too small. */
	outputBufferDesc.numSamples = pBinauralNode->iplAudioSettings.frameSize;
	outputBufferDesc.numChannels = 2;
	outputBufferDesc.data = pBinauralNode->ppBuffersOut;

	while (totalFramesProcessed < totalFramesToProcess)
	{
		ma_uint32 framesToProcessThisIteration = totalFramesToProcess - totalFramesProcessed;
		if (framesToProcessThisIteration > (ma_uint32)pBinauralNode->iplAudioSettings.frameSize)
		{
			framesToProcessThisIteration = (ma_uint32)pBinauralNode->iplAudioSettings.frameSize;
		}

		if (inputBufferDesc.numChannels == 1)
		{
			/* Fast path. No need for deinterleaving since it's a mono stream. */
			pBinauralNode->ppBuffersIn[0] = (float*)ma_offset_pcm_frames_const_ptr_f32(ppFramesIn[0], totalFramesProcessed, 1);
		}
		else
		{
			/* Slow path. Need to deinterleave the input data. */
			ma_deinterleave_pcm_frames(ma_format_f32, inputBufferDesc.numChannels, framesToProcessThisIteration, ma_offset_pcm_frames_const_ptr_f32(ppFramesIn[0], totalFramesProcessed, inputBufferDesc.numChannels), (void**)pBinauralNode->ppBuffersIn);
		}

		inputBufferDesc.data = pBinauralNode->ppBuffersIn;
		inputBufferDesc.numSamples = (IPLint32)framesToProcessThisIteration;

		/* Apply the effect. */
		iplBinauralEffectApply(pBinauralNode->iplEffect, &binauralParams, &inputBufferDesc, &outputBufferDesc);
		// iplDirectEffectApply(pBinauralNode->effect, &params, &inputBufferDesc, &outputBufferDesc);

		/* Interleave straight into the output buffer. */
		ma_interleave_pcm_frames(ma_format_f32, 2, framesToProcessThisIteration, (const void**)pBinauralNode->ppBuffersOut, ma_offset_pcm_frames_ptr_f32(ppFramesOut[0], totalFramesProcessed, 2));

		/* Advance. */
		totalFramesProcessed += framesToProcessThisIteration;
	}

	(void)pFrameCountIn; /* Unused. */
}

static ma_node_vtable g_ma_steamaudio_binaural_node_vtable =
{
	ma_steamaudio_binaural_node_process_pcm_frames,
	NULL,
	1, /* 1 input channel. */
	1, /* 1 output channel. */
	0 };

MA_API ma_result ma_steamaudio_binaural_node_init(ma_node_graph* pNodeGraph, const ma_steamaudio_binaural_node_config* pConfig, const ma_allocation_callbacks* pAllocationCallbacks, ma_steamaudio_binaural_node* pBinauralNode)
{
	ma_result result;
	ma_node_config baseConfig;
	ma_uint32 channelsIn;
	ma_uint32 channelsOut;
	IPLBinauralEffectSettings iplBinauralEffectSettings;
	IPLDirectEffectSettings effectSettings{};
	size_t heapSizeInBytes;

	if (pBinauralNode == NULL)
	{
		return MA_INVALID_ARGS;
	}

	MA_ZERO_OBJECT(pBinauralNode);

	if (pConfig == NULL || pConfig->iplAudioSettings.frameSize == 0 || pConfig->iplContext == NULL || pConfig->iplHRTF == NULL)
	{
		return MA_INVALID_ARGS;
	}

	/* Steam Audio only supports mono and stereo input. */
	if (pConfig->channelsIn < 1 || pConfig->channelsIn > 2)
	{
		return MA_INVALID_ARGS;
	}

	channelsIn = pConfig->channelsIn;
	channelsOut = 2; /* Always stereo output. */

	baseConfig = ma_node_config_init();
	baseConfig.vtable = &g_ma_steamaudio_binaural_node_vtable;
	baseConfig.pInputChannels = &channelsIn;
	baseConfig.pOutputChannels = &channelsOut;
	result = ma_node_init(pNodeGraph, &baseConfig, pAllocationCallbacks, &pBinauralNode->baseNode);
	if (result != MA_SUCCESS)
	{
		return result;
	}

	pBinauralNode->iplAudioSettings = pConfig->iplAudioSettings;
	pBinauralNode->iplContext = pConfig->iplContext;
	pBinauralNode->iplHRTF = pConfig->iplHRTF;

	MA_ZERO_OBJECT(&iplBinauralEffectSettings);
	iplBinauralEffectSettings.hrtf = pBinauralNode->iplHRTF;

	result = ma_result_from_IPLerror(iplBinauralEffectCreate(pBinauralNode->iplContext, &pBinauralNode->iplAudioSettings, &iplBinauralEffectSettings, &pBinauralNode->iplEffect));
	if (result != MA_SUCCESS)
	{
		ma_node_uninit(&pBinauralNode->baseNode, pAllocationCallbacks);
		return result;
	}
	heapSizeInBytes = 0;

	/*
	Unfortunately Steam Audio uses deinterleaved buffers for everything so we'll need to use some
	intermediary buffers. We'll allocate one big buffer on the heap and then use offsets. We'll
	use the frame size from the IPLAudioSettings structure as a basis for the size of the buffer.
	*/
	heapSizeInBytes += sizeof(float) * channelsOut * pBinauralNode->iplAudioSettings.frameSize; /* Output buffer. */
	heapSizeInBytes += sizeof(float) * channelsIn * pBinauralNode->iplAudioSettings.frameSize;	/* Input buffer. */

	pBinauralNode->_pHeap = ma_malloc(heapSizeInBytes, pAllocationCallbacks);
	if (pBinauralNode->_pHeap == NULL)
	{
		iplBinauralEffectRelease(&pBinauralNode->iplEffect);
		ma_node_uninit(&pBinauralNode->baseNode, pAllocationCallbacks);
		return MA_OUT_OF_MEMORY;
	}

	pBinauralNode->ppBuffersOut[0] = (float*)pBinauralNode->_pHeap;
	pBinauralNode->ppBuffersOut[1] = (float*)ma_offset_ptr(pBinauralNode->_pHeap, sizeof(float) * pBinauralNode->iplAudioSettings.frameSize);

	{
		ma_uint32 iChannelIn;
		for (iChannelIn = 0; iChannelIn < channelsIn; iChannelIn += 1)
		{
			pBinauralNode->ppBuffersIn[iChannelIn] = (float*)ma_offset_ptr(pBinauralNode->_pHeap, sizeof(float) * pBinauralNode->iplAudioSettings.frameSize * (channelsOut + iChannelIn));
		}
	}

	return MA_SUCCESS;
}

MA_API void ma_steamaudio_binaural_node_uninit(ma_steamaudio_binaural_node* pBinauralNode, const ma_allocation_callbacks* pAllocationCallbacks)
{
	if (pBinauralNode == NULL)
	{
		return;
	}

	/* The base node is always uninitialized first. */
	ma_node_uninit(&pBinauralNode->baseNode, pAllocationCallbacks);

	/*
	The Steam Audio objects are deleted after the base node. This ensures the base node is removed from the graph
	first to ensure these objects aren't getting used by the audio thread.
	*/
	iplBinauralEffectRelease(&pBinauralNode->iplEffect);
	ma_free(pBinauralNode->_pHeap, pAllocationCallbacks);
}

MA_API ma_result ma_steamaudio_binaural_node_set_direction(ma_steamaudio_binaural_node* pBinauralNode, float x, float y, float z)
{
	if (pBinauralNode == NULL)
	{
		return MA_INVALID_ARGS;
	}

	pBinauralNode->direction.x = x;
	pBinauralNode->direction.y = -y;
	pBinauralNode->direction.z = z;

	return MA_SUCCESS;
}

bool soundsystem_init()
{
	if (g_SoundInitialized == true)
		return true;
	output = new mixer(nullptr, true);
	sound_default_mixer = output; // This is in progress now. new mixer(output, false);
	ma_device_config devConfig = ma_device_config_init(ma_device_type_playback);
	;
	devConfig.noClip = MA_TRUE;
	devConfig.periodSizeInFrames = period_size;
	devConfig.playback.channels = CHANNELS;
	devConfig.sampleRate = SAMPLE_RATE;
	devConfig.playback.format = FORMAT;
	devConfig.dataCallback = sound_mixer_device_callback;
	if (ma_device_init(nullptr, &devConfig, &sound_mixer_device) != MA_SUCCESS)
		return false;
	MA_ZERO_OBJECT(&iplAudioSettings);
	iplAudioSettings.samplingRate = SAMPLE_RATE;

	iplAudioSettings.frameSize = devConfig.periodSizeInFrames;

	/* IPLContext */
	MA_ZERO_OBJECT(&iplContextSettings);
	iplContextSettings.version = STEAMAUDIO_VERSION;
	//    iplContextSettings.flags = IPL_CONTEXTFLAGS_VALIDATION;
	ma_result_from_IPLerror(iplContextCreate(&iplContextSettings, &iplContext));
	/* IPLHRTF */
	MA_ZERO_OBJECT(&iplHRTFSettings);
	iplHRTFSettings.type = IPL_HRTFTYPE_DEFAULT;
	iplHRTFSettings.volume = 1.0f;
	ma_result_from_IPLerror(iplHRTFCreate(iplContext, &iplAudioSettings, &iplHRTFSettings, &iplHRTF));
	ma_device_start(&sound_mixer_device);
	return true;
}

void soundsystem_free()
{
	if (g_SoundInitialized == false)
		return;
	if (sound_default_mixer) {
		delete sound_default_mixer;
		sound_default_mixer = nullptr;
	}
	iplHRTFRelease(&iplHRTF);
	iplContextRelease(&iplContext);
	ma_device_uninit(&sound_mixer_device);
	g_SoundInitialized = false;
}

string sound_path;
pack* sound_pack = nullptr;
void set_sound_storage(const string& path)
{
	sound_path = path;
	sound_pack = nullptr;
}
string get_sound_storage()
{
	return sound_path;
}
void set_sound_pack(pack* p)
{
	if (p == nullptr)
		return;
	sound_pack = p;
	sound_path = "";
}
pack* get_sound_pack()
{
	return sound_pack;
}
void set_master_volume(float volume)
{
	if (volume > 0 or volume < -100)
		return;
	if (output) ma_engine_set_volume(&output->m_mixer, ma_volume_linear_to_db(volume));
}
float get_master_volume()
{
	return output ? ma_volume_db_to_linear(ma_engine_get_volume(&output->m_mixer)) : 0.0f;
}
bool sound_global_hrtf = false;

class pcm_ring_buffer {
public:
	ma_pcm_rb rb;
	pcm_ring_buffer(ma_uint32 channels = 2, ma_uint32 sample_rate = SAMPLE_RATE, ma_uint32 bufferSizeInFrames = 1024)
		: ref_count(1) {
		if (ma_pcm_rb_init(ma_format_f32, channels, bufferSizeInFrames, nullptr, nullptr, &rb) != MA_SUCCESS) {
			throw std::runtime_error("Failed to initialize PCM ring buffer");
		}
		ma_pcm_rb_set_sample_rate(&rb, sample_rate);
	}

	~pcm_ring_buffer() {
		ma_pcm_rb_uninit(&rb);
	}

	void write(const std::string& data) {
		if (data.empty()) return;

		// Calculate the number of frames based on the size of the input data
		ma_uint32 sizeInFrames = static_cast<ma_uint32>(data.size() / (sizeof(float) * rb.channels)); // Assuming float samples
		void* bufferOut = nullptr;

		// Acquire space in the ring buffer
		if (ma_pcm_rb_acquire_write(&rb, &sizeInFrames, &bufferOut) != MA_SUCCESS) {
			return;
		}

		// Copy data into the ring buffer
		std::memcpy(bufferOut, data.data(), sizeInFrames * sizeof(float) * rb.channels);
		ma_pcm_rb_commit_write(&rb, sizeInFrames);
	}

	std::string read(size_t size) {
		void* bufferOut = nullptr;
		ma_uint32 sizeInFrames = static_cast<ma_uint32>(size / (sizeof(float) * rb.channels)); // Assuming float samples

		// Acquire space in the ring buffer for reading
		if (ma_pcm_rb_acquire_read(&rb, &sizeInFrames, &bufferOut) != MA_SUCCESS) {
			return "";
		}

		// Create a string to hold the read data
		std::string result(static_cast<char*>(bufferOut), sizeInFrames * sizeof(float) * rb.channels);
		ma_pcm_rb_commit_read(&rb, sizeInFrames);

		return result;
	}

	void reset() {
		ma_pcm_rb_reset(&rb);
	}

	// Reference counting methods
	void add_ref() {
		ref_count++;
	}

	void release() {
		if (--ref_count == 0) {
			delete this;
		}
	}

private:
	std::atomic<int> ref_count; // Atomic for thread safety
};





class MINIAUDIO_IMPLEMENTATION sound
{
public:
	bool is_3d_;
	bool playing = false, paused = false, active = false;
	ma_sound* handle_ = nullptr;
	ma_decoder decoder;
	bool decoderInitialized = false;
	ma_steamaudio_binaural_node m_binauralNode; /* The echo effect is achieved using a delay node. */
	ma_reverb_node m_reverbNode;				/* The reverb node. */
	ma_reverb_node_config reverbNodeConfig;
	ma_vocoder_node m_vocoderNode; /* The vocoder node. */
	ma_vocoder_node_config vocoderNodeConfig;
	ma_delay_node m_delayNode; /* The delay node. */
	ma_delay_node_config delayNodeConfig;
	ma_ltrim_node m_trimNode; /* The trim node. */
	ma_ltrim_node_config trimNodeConfig;
	ma_channel_separator_node m_separatorNode; /* The separator node. */
	ma_channel_combiner_node m_combinerNode;   /* The combiner node. */
	ma_channel_separator_node_config separatorNodeConfig;
	ma_channel_combiner_node_config combinerNodeConfig;
	ma_hpf_node highpass;
	ma_hpf_node_config highpassConfig;
	ma_lpf_node lowpass;
	ma_lpf_node_config lowpassConfig;
	ma_notch_node notch;
	ma_notch_node_config notchConfig;
	ma_steamaudio_binaural_node_config binauralNodeConfig;
	std::map<std::string, ma_node*> effects;
	ma_audio_buffer m_buffer;
	bool buffer_initialized = false;
	string file;
	Vector3 source_position;
	Vector3 listener_position;
	mixer* current_mixer = nullptr;
	mutable int ref = 0;
	sound(const string& filename = "")
	{
		ref = 1;
		if (!g_SoundInitialized)
		{
			g_SoundInitialized = soundsystem_init();
		}
		current_mixer = sound_default_mixer;
		set_mixer(current_mixer);
		effects["Default"] = ma_engine_get_endpoint(&current_mixer->m_mixer);
		if (filename != "")
			this->load(filename);
	}
	~sound()
	{
		if (active)
			this->close();
	}
	void AddRef() const
	{
		ref += 1;
	}
	void Release() const
	{
		if (--ref < 1)
		{
			delete this;
		}
	}

	bool load(const string& filename)
	{
		string result;
		if (sound_path != "")
		{
			result = sound_path + "/" + filename.c_str();
		}
		else
		{
			result = filename;
		}
		if (active)
			this->close();
		if (sound_pack != nullptr and sound_pack->active())
		{
			string file = sound_pack->get_file(filename);
			size_t size = sound_pack->get_file_size(filename);
			return this->load_from_memory(file, size);
		}
		handle_ = new ma_sound;
		ma_result loading_result = ma_sound_init_from_file(&current_mixer->m_mixer, result.c_str(), 0, NULL, NULL, handle_);
		if (loading_result != MA_SUCCESS)
		{
			delete handle_;
			active = false;
			return false;
		}
		active = true;
		file = result;
		auto last = --effects.end();
		if (last->second != nullptr)
			ma_node_attach_output_bus(handle_, 0, last->second, 0);

		if (sound_global_hrtf)
			this->set_hrtf(true);
		ma_sound_set_rolloff(handle_, 2);
		return true;
	}
	bool load_from_memory(const string& data, size_t stream_size)
	{
		if (active)
			this->close();
		handle_ = new ma_sound;
		ma_result r = ma_decoder_init_memory(data.c_str(), stream_size, NULL, &decoder);
		if (r != MA_SUCCESS)
			return false;
		ma_result loading_result = ma_sound_init_from_data_source(&current_mixer->m_mixer, &decoder, 0, 0, handle_);
		if (loading_result != MA_SUCCESS)
		{
			delete handle_;
			active = false;
			return false;
		}
		decoderInitialized = true;
		active = true;
		auto last = --effects.end();

		ma_node_attach_output_bus(handle_, 0, last->second, 0);

		if (sound_global_hrtf)
			this->set_hrtf(true);

		return active;
	}
	bool load_pcm(const string& data, size_t size, int channels, int sample_rate, int bits_per_sample)
	{
		if (active)
			this->close();
		handle_ = new ma_sound;
		if (buffer_initialized)
		{
			ma_audio_buffer_uninit(&m_buffer);
			buffer_initialized = false;
		}
		ma_audio_buffer_config bufferConfig = ma_audio_buffer_config_init(FORMAT, channels, size, (const void*)data.c_str(), nullptr);
		bufferConfig.sampleRate = sample_rate;
		bufferConfig.channels = channels;
		ma_format format = ma_format_unknown;
		switch (bits_per_sample) {
		case 8:
			format = ma_format_u8;
			break;
		case 16:
			format = ma_format_s16;
			break;
		case 24:
			format = ma_format_s24;
			break;
		case 32:
			format = ma_format_f32;
			break;
		default:
			break;
		}
		bufferConfig.format = format;
		ma_result result = ma_audio_buffer_init(&bufferConfig, &m_buffer);
		if (result != MA_SUCCESS)
			return false;
		buffer_initialized = true;
		ma_result loading_result = ma_sound_init_from_data_source(&current_mixer->m_mixer, &m_buffer, 0, 0, handle_);
		if (loading_result != MA_SUCCESS)
		{
			delete handle_;
			active = false;
			return false;
		}
		active = true;
		buffer_initialized = true;
		auto last = --effects.end();

		ma_node_attach_output_bus(handle_, 0, last->second, 0);

		if (sound_global_hrtf)
			this->set_hrtf(true);

		return active;
	}

	bool load_pcm_buffer(pcm_ring_buffer* buffer)
	{
		if (active)
			this->close();
		handle_ = new ma_sound;
		ma_result loading_result = ma_sound_init_from_data_source(&current_mixer->m_mixer, &buffer->rb, 0, 0, handle_);
		if (loading_result != MA_SUCCESS)
		{
			delete handle_;
			active = false;
			return false;
		}
		active = true;
		auto last = --effects.end();

		ma_node_attach_output_bus(handle_, 0, last->second, 0);

		if (sound_global_hrtf)
			this->set_hrtf(true);

		return active;
	}


	void set_mixer(mixer* new_mixer) {
		if (current_mixer == new_mixer)
			return;
		auto last = --effects.end();
		if (current_mixer)
		{
			current_mixer->sounds.erase(this);
			if (last->second != nullptr)
				ma_node_detach_output_bus(last->second, 0);
		}
		current_mixer = new_mixer;
		if (current_mixer)
		{
			current_mixer->sounds.insert(this);
			if (last->second != nullptr)
				ma_node_attach_output_bus(last->second, 0, current_mixer->output_node, 0);
		}
	}

	const void* push_memory()
	{
		if (!active)
			return "";
		return ma_sound_get_data_source(handle_);
	}
	string get_file_path()
	{
		return this->file;
	}
	void set_faid_time(float volume_beg, float volume_end, float time)
	{
		ma_sound_set_fade_in_milliseconds(handle_, volume_beg / 100, volume_end / 100, static_cast<ma_uint64>(time));
	}
	bool play()
	{
		if (!active)
			return false;
		ma_sound_set_looping(handle_, false);
		ma_sound_start(handle_);
		this->paused = false;
		return true;
	}
	bool play_looped()
	{
		if (!active)
			return false;

		ma_sound_set_looping(handle_, true);
		ma_sound_start(handle_);
		this->paused = false;

		return true;
	}
	bool pause()
	{
		if (!active)
			return false;
		ma_sound_stop(handle_);
		this->paused = true;

		return true;
	}
	bool play_wait()
	{
		this->play();
		while (true)
		{
			wait(1);
			bool ac = sound::is_playing();
			if (ac == false)
			{
				break;
			}
		}
		return true;
	}

	bool stop()
	{
		if (!active)
			return false;
		ma_sound_stop(handle_);
		ma_sound_seek_to_pcm_frame(handle_, 0);
		return true;
	}
	bool close()
	{
		if (!is_active())
			return false;
		if (effects.find("reverb") != effects.end())
		{
			ma_reverb_node_uninit(&m_reverbNode, NULL);
			effects["reverb"] = nullptr;
			effects.erase("reverb");
		}
		if (effects.find("vocoder") != effects.end())
		{

			ma_vocoder_node_uninit(&m_vocoderNode, NULL);
			effects["vocoder"] = nullptr;
			effects.erase("vocoder");
		}
		if (effects.find("delay") != effects.end())
		{
			ma_delay_node_uninit(&m_delayNode, NULL);
			effects["delay"] = nullptr;
			effects.erase("delay");
		}
		if (effects.find("ltrim") != effects.end())
		{
			ma_ltrim_node_uninit(&m_trimNode, NULL);
			effects["ltrim"] = nullptr;
			effects.erase("ltrim");
		}
		if (effects.find("combiner") != effects.end())
		{
			ma_channel_combiner_node_uninit(&m_combinerNode, NULL);
			effects["combiner"] = nullptr;
			effects.erase("combiner");
		}
		if (effects.find("separator") != effects.end())
		{
			ma_channel_separator_node_uninit(&m_separatorNode, NULL);
			effects["separator"] = nullptr;
			effects.erase("separator");
		}
		if (effects.find("highpass") != effects.end())
		{
			ma_hpf_node_uninit(&highpass, NULL);
			effects["highpass"] = nullptr;
			effects.erase("highpass");
		}
		if (effects.find("lowpass") != effects.end())
		{
			ma_lpf_node_uninit(&lowpass, NULL);
			effects["lowpass"] = nullptr;
			effects.erase("lowpass");
		}
		if (effects.find("notch") != effects.end())
		{

			ma_notch_node_uninit(&notch, NULL);
			effects["notch"] = nullptr;
			effects.erase("notch");
		}
		this->set_hrtf(false);
		if (decoderInitialized)
		{
			ma_decoder_uninit(&decoder);
			decoderInitialized = false;
		}
		if (buffer_initialized)
		{
			ma_audio_buffer_uninit(&m_buffer);
			buffer_initialized = false;
		}

		if (handle_ != nullptr)
		{
			ma_sound_uninit(handle_);
			delete handle_;
		}
		if (!file.empty())
			file.clear();
		source_position.x = 0;
		source_position.y = 0;
		source_position.z = 0;
		listener_position = source_position;
		handle_ = nullptr;
		active = false;
		return true;
	}

	void set_fx(const string& fx)
	{
		if (!active)
			return;
		if (effects.find(fx) != effects.end())
			return;
		if (fx == "reverb")
		{
			reverbNodeConfig = ma_reverb_node_config_init(CHANNELS, SAMPLE_RATE, 100, 100, 100);
			ma_reverb_node_init(ma_engine_get_node_graph(&current_mixer->m_mixer), &reverbNodeConfig, NULL, &m_reverbNode);
			auto last = --effects.end();
			ma_node_attach_output_bus(&m_reverbNode, 0, last->second, 0);
			ma_node_attach_output_bus(handle_, 0, &m_reverbNode, 0);
			effects[fx] = &m_reverbNode;
		}
		if (fx == "vocoder")
		{
			vocoderNodeConfig = ma_vocoder_node_config_init(CHANNELS, SAMPLE_RATE);
			ma_vocoder_node_init(ma_engine_get_node_graph(&current_mixer->m_mixer), &vocoderNodeConfig, NULL, &m_vocoderNode);
			auto last = --effects.end();

			ma_node_attach_output_bus(&m_vocoderNode, 0, last->second, 0);
			ma_node_attach_output_bus(handle_, 0, &m_vocoderNode, 0);
			effects[fx] = &m_vocoderNode;
		}
		if (fx == "delay")
		{
			delayNodeConfig = ma_delay_node_config_init(CHANNELS, SAMPLE_RATE, (100 * SAMPLE_RATE) / 1000, 0.5f);
			ma_delay_node_init(ma_engine_get_node_graph(&current_mixer->m_mixer), &delayNodeConfig, NULL, &m_delayNode);
			auto last = --effects.end();

			ma_node_attach_output_bus(&m_delayNode, 0, last->second, 0);
			ma_node_attach_output_bus(handle_, 0, &m_delayNode, 0);
			effects[fx] = &m_delayNode;
		}
		if (fx == "ltrim")
		{
			trimNodeConfig = ma_ltrim_node_config_init(CHANNELS, 0);
			trimNodeConfig.threshold = 0.3;
			ma_ltrim_node_init(ma_engine_get_node_graph(&current_mixer->m_mixer), &trimNodeConfig, NULL, &m_trimNode);
			auto last = --effects.end();

			ma_node_attach_output_bus(&m_trimNode, 0, last->second, 0);
			ma_node_attach_output_bus(handle_, 0, &m_trimNode, 0);
			effects[fx] = &m_trimNode;
		}
		if (fx == "channelsplit")
		{
			combinerNodeConfig = ma_channel_combiner_node_config_init(CHANNELS);
			ma_channel_combiner_node_init(ma_engine_get_node_graph(&current_mixer->m_mixer), &combinerNodeConfig, NULL, &m_combinerNode);
			ma_node_attach_output_bus(&m_combinerNode, 0, ma_engine_get_endpoint(&current_mixer->m_mixer), 0);
			effects["combiner"] = &m_combinerNode;
			separatorNodeConfig = ma_channel_separator_node_config_init(CHANNELS);
			ma_channel_separator_node_init(ma_engine_get_node_graph(&current_mixer->m_mixer), &separatorNodeConfig, NULL, &m_separatorNode);
			MA_ASSERT(ma_node_get_output_bus_count(&m_separatorNode) == ma_node_get_input_bus_count(&m_combinerNode));
			for (ma_uint32 iChannel = 0; iChannel < ma_node_get_output_bus_count(&m_separatorNode); iChannel += 1)
			{
				ma_node_attach_output_bus(&m_separatorNode, iChannel, &m_combinerNode, iChannel);
			}

			ma_node_attach_output_bus(handle_, 0, &m_separatorNode, 0);
			effects["separator"] = &m_separatorNode;
			effects[fx] = &m_separatorNode;
		}
		if (fx == "highpass")
		{
			highpassConfig = ma_hpf_node_config_init(CHANNELS, SAMPLE_RATE, 600, -10);
			ma_hpf_node_init(ma_engine_get_node_graph(&current_mixer->m_mixer), &highpassConfig, NULL, &highpass);
			auto last = --effects.end();

			ma_node_attach_output_bus(&highpass, 0, last->second, 0);
			ma_node_attach_output_bus(handle_, 0, &highpass, 0);
			effects[fx] = &highpass;
		}
		if (fx == "lowpass")
		{
			lowpassConfig = ma_lpf_node_config_init(CHANNELS, SAMPLE_RATE, 600, -10);
			ma_lpf_node_init(ma_engine_get_node_graph(&current_mixer->m_mixer), &lowpassConfig, NULL, &lowpass);
			auto last = --effects.end();

			ma_node_attach_output_bus(&lowpass, 0, last->second, 0);
			ma_node_attach_output_bus(handle_, 0, &lowpass, 0);
			effects[fx] = &lowpass;
		}
		if (fx == "notch")
		{
			notchConfig = ma_notch_node_config_init(CHANNELS, SAMPLE_RATE, 0, 300);
			ma_notch_node_init(ma_engine_get_node_graph(&current_mixer->m_mixer), &notchConfig, NULL, &notch);
			auto last = --effects.end();

			ma_node_attach_output_bus(&notch, 0, last->second, 0);
			ma_node_attach_output_bus(handle_, 0, &notch, 0);
			effects[fx] = &notch;
		}
	}
	void delete_fx(const string& fx)
	{
		if (!active)
			return;
		if (effects.find(fx) == effects.end())
			return;
		if (fx == "reverb")
		{
			ma_reverb_node_uninit(&m_reverbNode, NULL);
		}
		if (fx == "vocoder")
		{
			ma_vocoder_node_uninit(&m_vocoderNode, NULL);
		}
		if (fx == "delay")
		{
			ma_delay_node_uninit(&m_delayNode, NULL);
		}
		if (fx == "ltrim")
		{
			ma_ltrim_node_uninit(&m_trimNode, NULL);
		}
		if (fx == "channelsplit")
		{
			combinerNodeConfig = ma_channel_combiner_node_config_init(CHANNELS);
			ma_channel_combiner_node_uninit(&m_combinerNode, NULL);
			ma_channel_separator_node_uninit(&m_separatorNode, NULL);
		}
		if (fx == "highpass")
		{
			ma_hpf_node_uninit(&highpass, NULL);
		}
		if (fx == "lowpass")
		{
			ma_lpf_node_uninit(&lowpass, NULL);
		}
		if (fx == "notch")
		{
			ma_notch_node_uninit(&notch, NULL);
		}
		effects[fx] = nullptr;
		effects.erase(fx);

		auto last = --effects.end();

		ma_node_attach_output_bus(handle_, 0, last->second, 0);
		if (last->first == "hrtf")
		{
			this->set_hrtf(false);
			this->set_hrtf(true);
		}
	}
	void set_reverb_parameters(float dry, float wet, float room_size, float damping, float mode)
	{
		if (!active)
			return;
		verblib_set_dry(&m_reverbNode.reverb, dry);
		verblib_set_wet(&m_reverbNode.reverb, wet);
		verblib_set_room_size(&m_reverbNode.reverb, room_size);
		verblib_set_damping(&m_reverbNode.reverb, damping);
		verblib_set_mode(&m_reverbNode.reverb, mode);
	}
	void set_delay_parameters(float dry, float wet, float dcay)
	{
		if (!active)
			return;
		ma_delay_node_set_dry(&m_delayNode, dry);
		ma_delay_node_set_wet(&m_delayNode, wet);
		ma_delay_node_set_decay(&m_delayNode, dcay);
	}
	void set_position(float listener_x, float listener_y, float listener_z, float source_x, float source_y, float source_z, double theta, float pan_step, float volume_step, float behind_pitch_decrease, float start_pan, float start_volume, float start_pitch)
	{
		if (!active)
			return;
		float delta_x = 0;
		float delta_y = 0;
		float delta_z = 0;
		float final_pan = start_pan;
		float final_volume = start_volume;
		float final_pitch = start_pitch;
		float rotational_source_x = source_x;
		float rotational_source_y = source_y;
		// First, we calculate the x and y based on the theta the listener is facing.
		if (theta > 0.0)
		{
			rotational_source_x = (cos(theta) * (source_x - listener_x)) - (sin(theta) * (source_y - listener_y)) + listener_x;
			rotational_source_y = (sin(theta) * (source_x - listener_x)) + (cos(theta) * (source_y - listener_y)) + listener_y;
			source_x = rotational_source_x;
			source_y = rotational_source_y;
		}
		// Next, we calculate the delta between the listener and the source.
		if (source_x < listener_x)
		{
			delta_x = listener_x - source_x;
			final_pan -= (delta_x * pan_step);
			final_volume -= (delta_x * volume_step);
		}
		if (source_x > listener_x)
		{
			delta_x = source_x - listener_x;
			final_pan += (delta_x * pan_step);
			final_volume -= (delta_x * volume_step);
		}
		if (source_y < listener_y)
		{
			final_pitch -= abs(behind_pitch_decrease);
			delta_y = listener_y - source_y;
			final_volume -= (delta_y * volume_step);
		}
		if (source_y > listener_y)
		{
			delta_y = source_y - listener_y;
			final_volume -= (delta_y * volume_step);
		}
		if (source_z < listener_z)
		{
			final_pitch -= abs(behind_pitch_decrease);
			delta_z = listener_z - source_z;
			final_volume -= (delta_z * volume_step);
		}
		if (source_z > listener_z)
		{
			delta_z = source_z - listener_z;
			final_volume -= (delta_z * volume_step);
		}
		// Then we check if the calculated values are out of range, and fix them if that's the case.
		if (final_pan < -100)
		{
			final_pan = -100;
		}
		if (final_pan > 100)
		{
			final_pan = 100;
		}
		if (final_volume < -100)
		{
			final_volume = -100;
		}
		// Now we set the properties on the sound, provided that they are not already correct.
		ma_steamaudio_binaural_node_set_direction(&m_binauralNode, source_x - listener_x, source_y - listener_y, source_z - listener_z);
		if (this->get_pan() != final_pan && !this->get_hrtf())
			this->set_pan(final_pan);
		if (this->get_volume() != final_volume)
			this->set_volume(final_volume);
		if (this->get_pitch() != final_pitch)
			this->set_pitch(final_pitch);
		listener_position.x = listener_x;
		listener_position.y = listener_y;
		listener_position.z = listener_z;
		source_position.x = source_x;
		source_position.y = source_y;
		source_position.z = source_z;
	}
	void set_position(Vector3& listener, Vector3& source, double theta, float pan_step, float volume_step, float behind_pitch_decrease, float start_pan, float start_volume, float start_pitch)
	{
		if (!active)
			return;
		this->set_position(listener.x, listener.y, listener.z, source.x, source.y, source.z, theta, pan_step, volume_step, behind_pitch_decrease, start_pan, start_volume, start_pitch);
	}
	void set_hrtf(bool hrtf)
	{
		if (!active)
			return;
		if (hrtf)
		{
			if (effects.find("hrtf") != effects.end())
				return;

			binauralNodeConfig = ma_steamaudio_binaural_node_config_init(CHANNELS, iplAudioSettings, iplContext, iplHRTF);

			m_binauralNode.handle_ = *this->handle_;
			ma_steamaudio_binaural_node_init(ma_engine_get_node_graph(&current_mixer->m_mixer), &binauralNodeConfig, NULL, &m_binauralNode);
			/* Connect the output of the delay node to the input of the endpoint. */
			auto last = --effects.end();
			ma_node_attach_output_bus(&m_binauralNode, 0, last->second, 0);
			ma_node_attach_output_bus(handle_, 0, &m_binauralNode, 0);
			effects["hrtf"] = &m_binauralNode;
			ma_sound_set_directional_attenuation_factor(handle_, 0);
		}
		else
		{
			if (effects.find("hrtf") != effects.end())
			{

				ma_steamaudio_binaural_node_uninit(&m_binauralNode, NULL);
				effects["hrtf"] = nullptr;
				effects.erase("hrtf");
				ma_sound_set_directional_attenuation_factor(handle_, 1);

				auto last = --effects.end();

				ma_node_attach_output_bus(handle_, 0, last->second, 0);
			}
		}
	}
	bool get_hrtf()
	{
		return effects.find("hrtf") != effects.end();
	}
	Vector3 get_listener_position()
	{
		return listener_position;
	}
	Vector3 get_source_position()
	{
		return source_position;
	}
	void set_volume_step(float volume_step)
	{
		if (!active)
			return;
		ma_sound_set_rolloff(handle_, volume_step);
	}
	void set_pan_step(float pan_step)
	{
		if (!active)
			return;
		ma_sound_set_directional_attenuation_factor(handle_, pan_step);
	}
	void set_pitch_step(float pitch_step)
	{
		if (!active)
			return;
		ma_sound_set_doppler_factor(handle_, pitch_step);
	}
	bool seek(float new_position)
	{
		if (!active)
			return false;

		if (new_position > this->get_length() || new_position <= 0.0f)
			return false;

		// Convert milliseconds to PCM frames for seeking
		ma_uint64 pcm_frame = static_cast<ma_uint64>((new_position / 1000.0f) * SAMPLE_RATE);
		ma_sound_seek_to_pcm_frame(handle_, pcm_frame);

		return true;
	}

	void set_looping(bool looping)
	{
		if (!active)
			return;
		ma_sound_set_looping(handle_, looping);
	}
	bool get_looping() const
	{
		if (!active)
			return false;
		return ma_sound_is_looping(handle_);
	}
	float get_pan() const
	{
		if (!active)
			return -17435;

		float pan = 0;
		pan = ma_sound_get_pan(handle_);
		return pan * 100;
	}

	void set_pan(float pan)
	{
		if (!active)
			return;
		ma_sound_set_pan(handle_, pan / 100);
	}

	float get_volume() const
	{
		if (!active)
			return -17435;

		float volume = 0;

		volume = ma_sound_get_volume(handle_);
		return ma_volume_linear_to_db(volume);
	}
	void set_volume(float volume)
	{
		if (!active)
			return;
		if (volume > 0 or volume < -100)
			return;
		ma_sound_set_volume(handle_, ma_volume_db_to_linear(volume));
	}
	float get_pitch() const
	{
		if (!active)
			return -17435;
		float pitch = 0;
		pitch = ma_sound_get_pitch(handle_);
		return pitch * 100;
	}

	void set_pitch(float pitch)
	{
		if (!active)
			return;
		ma_sound_set_pitch(handle_, pitch / 100);
	}
	void set_speed(float speed)
	{
	}
	float get_speed() const
	{
		return 0.0f;
	}
	bool is_active() const
	{
		return active;
	}

	bool is_playing() const
	{
		if (!active)
			return false;
		return ma_sound_is_playing(handle_);
	}

	bool is_paused() const
	{
		if (!active)
			return false;
		return this->paused;
	}

	float get_position()
	{
		if (!active)
			return -17435;
		ma_uint64 position = 0;
		ma_sound_get_cursor_in_pcm_frames(handle_, &position);
		return static_cast<float>(position) / SAMPLE_RATE * 1000.0f;
	}

	float get_length()
	{
		if (!active)
			return -17435;

		ma_uint64 length = 0;
		ma_sound_get_length_in_pcm_frames(handle_, &length);

		// Convert PCM frames to milliseconds
		return static_cast<float>(length) / SAMPLE_RATE * 1000.0f;
	}

	void set_length(float length = 0.0f)
	{
		if (!active)
			return;

		if (length > this->get_length())
			return;

		// Convert milliseconds back to PCM frames for setting stop time
		ma_uint64 pcm_frames = static_cast<ma_uint64>((length / 1000.0f) * SAMPLE_RATE);
		ma_sound_set_stop_time_in_pcm_frames(handle_, pcm_frames);
	}

	float get_sample_rate() const
	{
		float rate = SAMPLE_RATE;
		return rate;
	}
};
void set_sound_global_hrtf(bool hrtf)
{
	sound_global_hrtf = hrtf;
}
bool get_sound_global_hrtf()
{
	return sound_global_hrtf;
}


static void audio_recorder_callback(ma_device* pDevice, void* pOutput, const void* pInput, ma_uint32 frameCount)
{
	std::vector<float>* data = static_cast<std::vector<float>*>(pDevice->pUserData);
	const float* in = (const float*)pInput; // Use const float* for input data

	// Process stereo input (2 channels)
	for (ma_uint32 i = 0; i < frameCount * 2; ++i) {
		data->push_back(in[i]);
	}

	(void)pOutput; // Suppress unused variable warning
}

class MINIAUDIO_IMPLEMENTATION audio_recorder
{
public:
	std::vector<float>* data = nullptr;
	ma_device_config deviceConfig;
	ma_device recording_device;
	bool m_Started = false;
	mutable std::atomic<int> ref = 0;
	bool m_RecordOutput = false;
	void AddRef()const {
		++ref;
	}
	void Release()const {
		if (--ref < 1) {
			delete this;
		}
	}
	audio_recorder() : ref(1) {
	}
	~audio_recorder() {
		if (m_Started)
			this->stop();
	}
	void start()
	{
		if (m_Started)this->stop();
		if (m_RecordOutput) {
			data = &g_OutputData;
			g_RecordOutput = true;
			m_Started = true;
			return;
		}
		else {
			data = new std::vector<float>;
		}
		deviceConfig = ma_device_config_init(ma_device_type_capture);
		if (g_InputDevice != nullptr) {
			deviceConfig.capture.pDeviceID = g_InputDevice;
		}
		deviceConfig.capture.format = ma_format_f32;
		deviceConfig.capture.channels = 2;
		deviceConfig.sampleRate = 44100;
		deviceConfig.dataCallback = audio_recorder_callback;
		deviceConfig.pUserData = data;

		if (ma_device_init(nullptr, &deviceConfig, &recording_device) != MA_SUCCESS) {
			m_Started = false;
			return;
		}
		ma_device_start(&recording_device);
	}

	void stop()
	{
		if (!m_Started)return;
		if (m_RecordOutput) {
			data = nullptr;
			g_RecordOutput = false;
			m_Started = false;
			return;
		}
		ma_device_uninit(&recording_device);
	}

	std::string get_data(size_t& size)
	{
		if (!data)return "";
		size = data->size();
		std::string result(size * sizeof(float), '\0'); // Resize to hold all bytes

		// Copy float data to string as bytes
		std::memcpy(&result[0], data->data(), size * sizeof(float));

		return result;
	}

	void clear() {
		if (!data)return;
		data->clear();
	}
};

audio_recorder* faudio_recorder() {
	return new audio_recorder();
}

audio_recorder g_OutputRecorder;

audio_recorder* get_output_audio_recorder() {
	g_OutputRecorder.m_RecordOutput = true;
	g_OutputRecorder.AddRef();
	return &g_OutputRecorder;
}

sound* fsound(const string& filename) { return new sound(filename); }
pcm_ring_buffer* fbuffer(ma_uint32 channels, ma_uint32 sample_rate, ma_uint32 buffer_size = 1024) { return new pcm_ring_buffer(channels, sample_rate, buffer_size); }

void register_sound(asIScriptEngine* engine)
{
	engine->RegisterFuncdef("void sound_end_callback(const ?&in=null)");
	engine->RegisterGlobalFunction("void set_sound_storage(const string &in folder_name)property", asFUNCTION(set_sound_storage), asCALL_CDECL);

	engine->RegisterGlobalFunction("string get_sound_storage()property", asFUNCTION(get_sound_storage), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_sound_pack(pack@ pack_handle)property", asFUNCTION(set_sound_pack), asCALL_CDECL);

	engine->RegisterGlobalFunction("pack@ get_sound_pack()property", asFUNCTION(get_sound_pack), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_master_volume(float volume)property", asFUNCTION(set_master_volume), asCALL_CDECL);
	engine->RegisterGlobalFunction("float get_master_volume()property", asFUNCTION(get_master_volume), asCALL_CDECL);
	engine->RegisterGlobalFunction("array<string>@ get_output_audio_devices()", asFUNCTION(get_output_audio_devices), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool set_output_audio_device(uint index)", asFUNCTION(set_output_audio_device), asCALL_CDECL);

	engine->RegisterGlobalFunction("array<string>@ get_input_audio_devices()", asFUNCTION(get_input_audio_devices), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool set_input_audio_device(uint index)", asFUNCTION(set_input_audio_device), asCALL_CDECL);

	engine->RegisterObjectType("pcm_ring_buffer", sizeof(pcm_ring_buffer), asOBJ_REF);
	engine->RegisterObjectBehaviour("pcm_ring_buffer", asBEHAVE_FACTORY, "pcm_ring_buffer@ buff(uint32 channels = 2, uint32 sample_rate = 44100, uint32 size = 1024)", asFUNCTION(fbuffer), asCALL_CDECL);
	engine->RegisterObjectBehaviour("pcm_ring_buffer", asBEHAVE_ADDREF, "void f()", asMETHOD(pcm_ring_buffer, add_ref), asCALL_THISCALL);
	engine->RegisterObjectBehaviour("pcm_ring_buffer", asBEHAVE_RELEASE, "void f()", asMETHOD(pcm_ring_buffer, release), asCALL_THISCALL);
	engine->RegisterObjectMethod("pcm_ring_buffer", "void write(const string &in data)", asMETHOD(pcm_ring_buffer, write), asCALL_THISCALL);
	engine->RegisterObjectMethod("pcm_ring_buffer", "string read(size_t size)", asMETHOD(pcm_ring_buffer, read), asCALL_THISCALL);
	engine->RegisterObjectMethod("pcm_ring_buffer", "void reset()", asMETHOD(pcm_ring_buffer, reset), asCALL_THISCALL);



	engine->RegisterObjectType("sound", sizeof(sound), asOBJ_REF);
	engine->RegisterObjectBehaviour("sound", asBEHAVE_FACTORY, "sound@ s(const string &in filename = \"\")", asFUNCTION(fsound), asCALL_CDECL);
	engine->RegisterObjectBehaviour("sound", asBEHAVE_ADDREF, "void f()", asMETHOD(sound, AddRef), asCALL_THISCALL);
	engine->RegisterObjectBehaviour("sound", asBEHAVE_RELEASE, "void f()", asMETHOD(sound, Release), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "bool load(const string &in filename)const", asMETHOD(sound, load), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "bool load_from_memory(const string&in memory, size_t memory_size = 0)const", asMETHOD(sound, load_from_memory), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "bool load_pcm(const string&in memory, size_t memory_size = 0, int channels = 0, int sample_rate = 0, int bits_per_sample = 0)const", asMETHOD(sound, load_pcm), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "bool load_pcm_buffer(pcm_ring_buffer@ buffer)const", asMETHOD(sound, load_pcm_buffer), asCALL_THISCALL);


	engine->RegisterObjectMethod(_O("sound"), "uint64 push_memory()const", asMETHOD(sound, push_memory), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "string get_file_path()const property", asMETHOD(sound, get_file_path), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "void set_faid_time(float volume_beg, float volume_end, float time)const", asMETHOD(sound, set_faid_time), asCALL_THISCALL);

	engine->RegisterObjectMethod(_O("sound"), "bool play()const", asMETHOD(sound, play), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "bool play_looped()const", asMETHOD(sound, play_looped), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "bool pause()const", asMETHOD(sound, pause), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "bool play_wait()const", asMETHOD(sound, play_wait), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "bool stop()const", asMETHOD(sound, stop), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "bool close()const", asMETHOD(sound, close), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "void set_fx(const string &in effect_name, int=0)const", asMETHOD(sound, set_fx), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "void delete_fx(const string &in effect_name, int=0)const", asMETHOD(sound, delete_fx), asCALL_THISCALL);

	engine->RegisterObjectMethod(_O("sound"), "void set_reverb_parameters(float dry, float wet, float room_size, float damping, float mode)const", asMETHOD(sound, set_reverb_parameters), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "void set_delay_parameters(float dry, float wet, float dcay)const", asMETHOD(sound, set_delay_parameters), asCALL_THISCALL);

	engine->RegisterObjectMethod(_O("sound"), "void set_position(float listener_x, float listener_y, float listener_z, float source_x, float source_y, float source_z, double theta = 0.0, float pan_step = 5, float volume_step = 0.5, float behind_pitch_decrease = 0.0, float start_pan = 0, float start_volume = 0, float start_pitch = 0)const", asMETHODPR(sound, set_position, (float listener_x, float listener_y, float listener_z, float source_x, float source_y, float source_z, double theta, float pan_step, float volume_step, float behind_pitch_decrease, float start_pan, float start_volume, float start_pitch), void), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "void set_position(vector&in listener, vector&in source, double theta = 0.0, float pan_step = 5, float volume_step = 0.5, float behind_pitch_decrease = 0.0, float start_pan = 0, float start_volume = 0, float start_pitch = 0)const", asMETHODPR(sound, set_position, (Vector3&, Vector3&, double theta, float pan_step, float volume_step, float behind_pitch_decrease, float start_pan, float start_volume, float start_pitch), void), asCALL_THISCALL);

	engine->RegisterObjectMethod(_O("sound"), "void set_hrtf(bool hrtf = true)const property", asMETHOD(sound, set_hrtf), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "bool get_hrtf()const property", asMETHOD(sound, get_hrtf), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "vector get_listener_position()const property", asMETHOD(sound, get_listener_position), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "vector get_source_position()const property", asMETHOD(sound, get_source_position), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "bool seek(float pos)const", asMETHOD(sound, seek), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "bool get_looping() const property", asMETHOD(sound, get_looping), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "void set_looping(bool)const property", asMETHOD(sound, set_looping), asCALL_THISCALL);

	engine->RegisterObjectMethod(_O("sound"), "float get_pan() const property", asMETHOD(sound, get_pan), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "void set_pan(float)const property", asMETHOD(sound, set_pan), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "float get_volume() const property", asMETHOD(sound, get_volume), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "void set_volume(float)const property", asMETHOD(sound, set_volume), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "float get_pitch() const property", asMETHOD(sound, get_pitch), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "void set_pitch(float)const property", asMETHOD(sound, set_pitch), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "float get_speed() const property", asMETHOD(sound, get_speed), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "void set_speed(float)const property", asMETHOD(sound, set_speed), asCALL_THISCALL);

	engine->RegisterObjectMethod(_O("sound"), "bool get_active() const property", asMETHOD(sound, is_active), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "bool get_playing() const property", asMETHOD(sound, is_playing), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "bool get_paused() const property", asMETHOD(sound, is_paused), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "float get_position() const property", asMETHOD(sound, get_position), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "float get_length() const property", asMETHOD(sound, get_length), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("sound"), "void set_length(float=0.0) const property", asMETHOD(sound, set_length), asCALL_THISCALL);

	engine->RegisterObjectMethod(_O("sound"), "float get_sample_rate() const property", asMETHOD(sound, get_sample_rate), asCALL_THISCALL);
	engine->RegisterGlobalFunction("void set_sound_global_hrtf(bool)property", asFUNCTION(set_sound_global_hrtf), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool get_sound_global_hrtf()property", asFUNCTION(get_sound_global_hrtf), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_spatial_blend_max_distance(float)property", asFUNCTION(set_spatial_blend_max_distance), asCALL_CDECL);
	engine->RegisterGlobalFunction("float get_spatial_blend_max_distance()property", asFUNCTION(get_spatial_blend_max_distance), asCALL_CDECL);

	engine->RegisterObjectType("audio_recorder", sizeof(audio_recorder), asOBJ_REF);
	engine->RegisterObjectBehaviour("audio_recorder", asBEHAVE_FACTORY, "audio_recorder@ s()", asFUNCTION(faudio_recorder), asCALL_CDECL);
	engine->RegisterObjectBehaviour("audio_recorder", asBEHAVE_ADDREF, "void f()", asMETHOD(audio_recorder, AddRef), asCALL_THISCALL);
	engine->RegisterObjectBehaviour("audio_recorder", asBEHAVE_RELEASE, "void f()", asMETHOD(audio_recorder, Release), asCALL_THISCALL);

	engine->RegisterObjectMethod(_O("audio_recorder"), "void start()const", asMETHOD(audio_recorder, start), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("audio_recorder"), "void stop()const", asMETHOD(audio_recorder, stop), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("audio_recorder"), "string get_data(size_t&out size = void)const", asMETHOD(audio_recorder, get_data), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("audio_recorder"), "void clear()const", asMETHOD(audio_recorder, clear), asCALL_THISCALL);

	engine->RegisterGlobalFunction("audio_recorder@ get_output_audio_recorder() property", asFUNCTION(get_output_audio_recorder), asCALL_CDECL);

}
