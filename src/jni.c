#include <jni.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "oprf.h"
#include "toprf.h"
#include "tp-dkg.h"

JNIEXPORT jobject JNICALL Java_org_hsbp_androsphinx_Oprf_blind(JNIEnv *env, jobject ignore, jbyteArray inputValue) {
	jobject result = NULL;

	jbyte* bufferPtrInputValue = (*env)->GetByteArrayElements(env, inputValue, NULL);
	jsize inputValueLen = (*env)->GetArrayLength(env, inputValue);

	jbyteArray r = (*env)->NewByteArray(env, crypto_core_ristretto255_SCALARBYTES);
	jbyteArray blinded = (*env)->NewByteArray(env, crypto_core_ristretto255_BYTES);

	jbyte *bufferPtrR = (*env)->GetByteArrayElements(env, r, NULL);
	jbyte *bufferPtrBlinded = (*env)->GetByteArrayElements(env, blinded, NULL);

	if (oprf_Blind((const uint8_t*)bufferPtrInputValue, inputValueLen,
				(uint8_t*)bufferPtrR,
				(uint8_t*)bufferPtrBlinded) == 0) {
		(*env)->ReleaseByteArrayElements(env, r, bufferPtrR, 0);
		(*env)->ReleaseByteArrayElements(env, blinded, bufferPtrBlinded, 0);

		jclass clazz = (*env)->FindClass(env, "kotlin/Pair");
		jmethodID constructor = (*env)->GetMethodID(env, clazz, "<init>", "(Ljava/lang/Object;Ljava/lang/Object;)V");
		result = (*env)->NewObject(env, clazz, constructor, r, blinded);
	} else {
		(*env)->ReleaseByteArrayElements(env, r, bufferPtrR, JNI_ABORT);
		(*env)->ReleaseByteArrayElements(env, blinded, bufferPtrBlinded, JNI_ABORT);
	}

	(*env)->ReleaseByteArrayElements(env, inputValue, bufferPtrInputValue, JNI_ABORT);
	return result;
}


JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Oprf_evaluate(JNIEnv *env, jobject ignore, jbyteArray key, jbyteArray blinded) {
	if (key == NULL || blinded == NULL ||
			(*env)->GetArrayLength(env, key) != crypto_core_ristretto255_SCALARBYTES ||
			(*env)->GetArrayLength(env, blinded) != crypto_core_ristretto255_BYTES) {
		return NULL;
	}

	jbyteArray result = NULL;
	jbyteArray z = (*env)->NewByteArray(env, crypto_core_ristretto255_BYTES);
	jbyte *bufferPtrZ = (*env)->GetByteArrayElements(env, z, NULL);
	jbyte *bufferPtrBlinded = (*env)->GetByteArrayElements(env, blinded, NULL);
	jbyte *bufferPtrKey = (*env)->GetByteArrayElements(env, key, NULL);

	if (oprf_Evaluate((const uint8_t*)bufferPtrKey, (const uint8_t*)bufferPtrBlinded,
				(uint8_t*)bufferPtrZ) == 0) {
		(*env)->ReleaseByteArrayElements(env, z, bufferPtrZ, 0);
		result = z;
	} else {
		(*env)->ReleaseByteArrayElements(env, z, bufferPtrZ, JNI_ABORT);
	}

	(*env)->ReleaseByteArrayElements(env, key, bufferPtrKey, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, blinded, bufferPtrBlinded, JNI_ABORT);
	return result;
}


JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Oprf_unblindFinalize(JNIEnv *env, jobject ignore, jbyteArray r, jbyteArray z, jbyteArray x) {
	if (r == NULL || z == NULL || x == NULL || 
			(*env)->GetArrayLength(env, r) != crypto_core_ristretto255_SCALARBYTES ||
			(*env)->GetArrayLength(env, z) != crypto_core_ristretto255_BYTES) {
		return NULL;
	}
	
	jbyte n[crypto_core_ristretto255_BYTES];
	jbyteArray result = NULL;

	jbyte *bufferPtrR = (*env)->GetByteArrayElements(env, r, NULL);
	jbyte *bufferPtrZ = (*env)->GetByteArrayElements(env, z, NULL);
	
	if (oprf_Unblind((const uint8_t*)bufferPtrR, (const uint8_t*)bufferPtrZ,
				(uint8_t*)n) == 0) {
		jbyte *bufferPtrX = (*env)->GetByteArrayElements(env, x, NULL);
		jsize xLen = (*env)->GetArrayLength(env, x);

		jbyteArray y = (*env)->NewByteArray(env, OPRF_BYTES);
		jbyte *bufferPtrY = (*env)->GetByteArrayElements(env, y, NULL);

		if (oprf_Finalize((const uint8_t*)bufferPtrX, xLen, (const uint8_t*)n,
					(uint8_t*)bufferPtrY) == 0) {
			result = y;
			(*env)->ReleaseByteArrayElements(env, y, bufferPtrY, 0);
		} else {
			(*env)->ReleaseByteArrayElements(env, y, bufferPtrY, JNI_ABORT);
		}
		
		(*env)->ReleaseByteArrayElements(env, x, bufferPtrX, JNI_ABORT);
	}

	(*env)->ReleaseByteArrayElements(env, r, bufferPtrR, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, z, bufferPtrZ, JNI_ABORT);
	return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Oprf_scalarMultRistretto255base(JNIEnv *env, jobject ignore, jbyteArray r) {
	if (r == NULL || (*env)->GetArrayLength(env,  r) != crypto_core_ristretto255_SCALARBYTES) return NULL;

	jbyteArray gr = (*env)->NewByteArray(env, crypto_core_ristretto255_BYTES);
	jbyte *bufferPtrR  = (*env)->GetByteArrayElements(env,  r, NULL);
	jbyte *bufferPtrGr = (*env)->GetByteArrayElements(env, gr, NULL);

	crypto_scalarmult_ristretto255_base((uint8_t*)bufferPtrGr, (const uint8_t*)bufferPtrR);

	(*env)->ReleaseByteArrayElements(env,  r, bufferPtrR, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, gr, bufferPtrGr, 0);
	return gr;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Oprf_thresholdMult(JNIEnv *env, jobject ignore, jobject responses) {
	if (responses == NULL) return NULL;
	jclass list = (*env)->FindClass(env, "java/util/List");
	jmethodID listSize = (*env)->GetMethodID(env, list, "size", "()I");
	jint responsesSize = (*env)->CallIntMethod(env, responses, listSize);
	if (responsesSize < 2) return NULL;

	jclass iterable = (*env)->FindClass(env, "java/lang/Iterable");
	jmethodID iterableIterator = (*env)->GetMethodID(env, iterable, "iterator", "()Ljava/util/Iterator;");
	jobject responsesIterator = (*env)->CallObjectMethod(env, responses, iterableIterator);
	if (responsesIterator == NULL) return NULL;

	jbyte responsesBuf[responsesSize * TOPRF_Part_BYTES];

	jclass iterator = (*env)->FindClass(env, "java/util/Iterator");
	jmethodID iteratorHasNext = (*env)->GetMethodID(env, iterator, "hasNext", "()Z");
	jmethodID iteratorNext = (*env)->GetMethodID(env, iterator, "next", "()Ljava/lang/Object;");
	jclass byteArray = (*env)->FindClass(env, "[B");

	jsize offset = 0;
	while ((*env)->CallBooleanMethod(env, responsesIterator, iteratorHasNext) == JNI_TRUE) {
		if (offset >= responsesSize) return NULL; /* should not happen, yet impl's can cheat */
		jobject item = (*env)->CallObjectMethod(env, responsesIterator, iteratorNext);
		if (item == NULL) return NULL;
		if ((*env)->IsInstanceOf(env, item, byteArray) == JNI_FALSE) return NULL;
		jbyteArray arrayItem = (jbyteArray)item;
		if ((*env)->GetArrayLength(env, arrayItem) != TOPRF_Part_BYTES) return NULL;
		(*env)->GetByteArrayRegion(env, arrayItem, 0, TOPRF_Part_BYTES, responsesBuf + offset++ * TOPRF_Part_BYTES);
	}

	jbyteArray result = (*env)->NewByteArray(env, crypto_core_ristretto255_BYTES);
	jbyte *bufferPtrResult = (*env)->GetByteArrayElements(env, result, NULL);
	if (toprf_thresholdmult(responsesSize,
				(const uint8_t(*)[33])responsesBuf,
				(uint8_t*)bufferPtrResult) == 0) {
		(*env)->ReleaseByteArrayElements(env, result, bufferPtrResult, 0);
		return result;
	} else {
		(*env)->ReleaseByteArrayElements(env, result, bufferPtrResult, JNI_ABORT);
		return NULL;
	}
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Oprf_tpDkgStartTp(JNIEnv *env, jobject ignore, jbyte n, jbyte t, jlong tsEpsilon, jstring protoName, jobject peerLongTermPublicKeysList) {
	if (protoName == NULL || peerLongTermPublicKeysList == NULL) return NULL;

	jbyte *buf = malloc(tpdkg_tpstate_size() + 32);
	fprintf(stderr, "buf = %p\n", buf);
	jbyte *ctx = buf + (32 - ((unsigned long long)buf % 32));
	fprintf(stderr, "ctx = %p\n", ctx);

	jbyteArray msg = (*env)->NewByteArray(env, tpdkg_msg0_SIZE);
	fprintf(stderr, "msg = %p\n", msg);
	jbyte *bufferPtrMsg = (*env)->GetByteArrayElements(env, msg, NULL);
	fprintf(stderr, "bufferPtrMsg = %p\n", bufferPtrMsg);
	const char *protoNameChars = (*env)->GetStringUTFChars(env, protoName, NULL);
	fprintf(stderr, "protoNameChars = %p\n", protoNameChars);
	jsize protoNameLen = (*env)->GetStringUTFLength(env, protoName);
	fprintf(stderr, "protoNameLen = %d\n", protoNameLen);
	
	int st_result = tpdkg_start_tp((TP_DKG_TPState*)ctx, tsEpsilon, n, t, protoNameChars, protoNameLen, tpdkg_msg0_SIZE, (DKG_Message*)bufferPtrMsg);

	fprintf(stderr, "tpdkg_start_tp() result = %08x\n", st_result);

	(*env)->ReleaseStringUTFChars(env, protoName, protoNameChars);

	uint8_t (*peersSignaturePublicKeys)[][crypto_sign_PUBLICKEYBYTES] = malloc(n * crypto_sign_PUBLICKEYBYTES);
	fprintf(stderr, "peersSignaturePublicKeys = %p\n", peersSignaturePublicKeys);
	uint8_t (*commitments)[][crypto_core_ristretto255_BYTES] = malloc(n * t * crypto_core_ristretto255_BYTES);
	fprintf(stderr, "commitments = %p\n", commitments);
	uint16_t (*complaints)[] = malloc(n * n * 2);
	fprintf(stderr, "complaints = %p\n", complaints);
	uint8_t (*noisyShares)[][tpdkg_msg8_SIZE] = malloc(n * n * tpdkg_msg8_SIZE);
	fprintf(stderr, "noisyShares = %p\n", noisyShares);
	size_t cheatersLen = sizeof(tpdkg_msg8_SIZE) * (t * t - 1); 
	fprintf(stderr, "cheatersLen = %zu\n", cheatersLen);
	TP_DKG_Cheater (*cheaters)[] = malloc(cheatersLen);
	fprintf(stderr, "cheaters = %p\n", cheaters);
	uint64_t *lastTimestamps = malloc(n * 8);
	fprintf(stderr, "lastTimestamps = %p\n", lastTimestamps);

	jclass list = (*env)->FindClass(env, "java/util/List");
	fprintf(stderr, "list = %p\n", list);
	jmethodID listSize = (*env)->GetMethodID(env, list, "size", "()I");
	fprintf(stderr, "listSize = %p\n", listSize);
	jint pkListSize = (*env)->CallIntMethod(env, peerLongTermPublicKeysList, listSize);
	fprintf(stderr, "pkListSize = %d\n", pkListSize);
	uint8_t (*peerLongTermPublicKeys)[][crypto_sign_PUBLICKEYBYTES] = malloc(pkListSize * crypto_sign_PUBLICKEYBYTES);

	jclass iterable = (*env)->FindClass(env, "java/lang/Iterable");
	fprintf(stderr, "iterable = %p\n", iterable);
	jmethodID iterableIterator = (*env)->GetMethodID(env, iterable, "iterator", "()Ljava/util/Iterator;");
	fprintf(stderr, "iterableIterator = %p\n", iterableIterator);
	jobject pkListIterator = (*env)->CallObjectMethod(env, peerLongTermPublicKeysList, iterableIterator);
	fprintf(stderr, "pkListIterator = %p\n", pkListIterator);

	if (pkListIterator == NULL) return NULL;

	jclass iterator = (*env)->FindClass(env, "java/util/Iterator");
	jmethodID iteratorHasNext = (*env)->GetMethodID(env, iterator, "hasNext", "()Z");
	jmethodID iteratorNext = (*env)->GetMethodID(env, iterator, "next", "()Ljava/lang/Object;");
	jclass byteArray = (*env)->FindClass(env, "[B");

	jsize offset = 0;
	while ((*env)->CallBooleanMethod(env, pkListIterator, iteratorHasNext) == JNI_TRUE) {
		if (offset >= pkListSize) return NULL; /* should not happen, yet impl's can cheat */
		jobject item = (*env)->CallObjectMethod(env, pkListIterator, iteratorNext);
		if (item == NULL) return NULL;
		if ((*env)->IsInstanceOf(env, item, byteArray) == JNI_FALSE) return NULL;
		jbyteArray arrayItem = (jbyteArray)item;
		if ((*env)->GetArrayLength(env, arrayItem) != crypto_sign_PUBLICKEYBYTES) return NULL;
		(*env)->GetByteArrayRegion(env, arrayItem, 0, crypto_sign_PUBLICKEYBYTES, (jbyte*)peerLongTermPublicKeys + offset++ * crypto_sign_PUBLICKEYBYTES);
	}

	for (int i = 0; i < pkListSize * crypto_sign_PUBLICKEYBYTES; i++) {
		fprintf(stderr, "%02hhx", ((jbyte*)peerLongTermPublicKeys)[i]);
	}
	fprintf(stderr, "\n");

	tpdkg_tp_set_bufs((TP_DKG_TPState*)ctx, commitments, complaints, noisyShares, cheaters, cheatersLen, peersSignaturePublicKeys, peerLongTermPublicKeys, lastTimestamps);

	jclass ctxClass = (*env)->FindClass(env, "org/hsbp/androsphinx/TpdkgContext");
	jmethodID ctxConstructor = (*env)->GetMethodID(env, ctxClass, "<init>", "(JJ)V");
	jobject ctxObj = (*env)->NewObject(env, ctxClass, ctxConstructor, ctx, buf);

	jclass pair = (*env)->FindClass(env, "kotlin/Pair");
	jmethodID pairConstructor = (*env)->GetMethodID(env, pair, "<init>", "(Ljava/lang/Object;Ljava/lang/Object;)V");
	jobject result = (*env)->NewObject(env, pair, pairConstructor, ctxObj, msg);

	(*env)->ReleaseByteArrayElements(env, msg, bufferPtrMsg, st_result ? JNI_ABORT : 0);
	return st_result ? NULL : result;
}

JNIEXPORT jbyte JNICALL Java_org_hsbp_androsphinx_TpdkgContext_getN(JNIEnv *env, jobject ctxObj) {
	const jclass ctxClass = (*env)->FindClass(env, "org/hsbp/androsphinx/TpdkgContext");
	const jfieldID ctxField = (*env)->GetFieldID(env, ctxClass, "ctx", "J");
	const jlong ctxValue = (*env)->GetLongField(env, ctxObj, ctxField);
	const TP_DKG_TPState *state = (TP_DKG_TPState*)ctxValue;
	return tpdkg_tpstate_n(state);
}

JNIEXPORT jbyte JNICALL Java_org_hsbp_androsphinx_TpdkgContext_getT(JNIEnv *env, jobject ctxObj) {
	const jclass ctxClass = (*env)->FindClass(env, "org/hsbp/androsphinx/TpdkgContext");
	const jfieldID ctxField = (*env)->GetFieldID(env, ctxClass, "ctx", "J");
	const jlong ctxValue = (*env)->GetLongField(env, ctxObj, ctxField);
	const TP_DKG_TPState *state = (TP_DKG_TPState*)ctxValue;
	return tpdkg_tpstate_t(state);
}

JNIEXPORT jint JNICALL Java_org_hsbp_androsphinx_TpdkgContext_getStep(JNIEnv *env, jobject ctxObj) {
	const jclass ctxClass = (*env)->FindClass(env, "org/hsbp/androsphinx/TpdkgContext");
	const jfieldID ctxField = (*env)->GetFieldID(env, ctxClass, "ctx", "J");
	const jlong ctxValue = (*env)->GetLongField(env, ctxObj, ctxField);
	const TP_DKG_TPState *state = (TP_DKG_TPState*)ctxValue;
	return tpdkg_tpstate_step(state);
}

JNIEXPORT jboolean JNICALL Java_org_hsbp_androsphinx_TpdkgContext_isNotDone(JNIEnv *env, jobject ctxObj) {
	const jclass ctxClass = (*env)->FindClass(env, "org/hsbp/androsphinx/TpdkgContext");
	const jfieldID ctxField = (*env)->GetFieldID(env, ctxClass, "ctx", "J");
	const jlong ctxValue = (*env)->GetLongField(env, ctxObj, ctxField);
	const TP_DKG_TPState *state = (TP_DKG_TPState*)ctxValue;
	return tpdkg_tp_not_done(state) == 1 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_TpdkgContext_next(JNIEnv *env, jobject ctxObj, jbyteArray msg) {
	if (msg == NULL) return NULL;
	const jclass ctxClass = (*env)->FindClass(env, "org/hsbp/androsphinx/TpdkgContext");
	const jfieldID ctxField = (*env)->GetFieldID(env, ctxClass, "ctx", "J");
	const jlong ctxValue = (*env)->GetLongField(env, ctxObj, ctxField);
	TP_DKG_TPState *state = (TP_DKG_TPState*)ctxValue;

	jsize msgLen = (*env)->GetArrayLength(env, msg);
	if (tpdkg_tp_input_size(state) != msgLen) {
		fprintf(stderr, "input size is %d byte(s) long, should be %zu byte(s) long\n",
				msgLen, tpdkg_tp_input_size(state));
		return NULL;
	}
	jsize outLen = tpdkg_tp_output_size(state);
	jbyteArray result = (*env)->NewByteArray(env, outLen);
	jbyte* bufferPtrResult = (*env)->GetByteArrayElements(env, result, NULL);
	jbyte* bufferPtrMsg = (*env)->GetByteArrayElements(env, msg, NULL);
	int ret = tpdkg_tp_next(state, (uint8_t*)bufferPtrMsg, msgLen,
			(uint8_t*)bufferPtrResult, outLen);
	if (ret != 0) {
		fprintf(stderr, "tpdkg_tp_next() returned %d\n", ret);
	}
	(*env)->ReleaseByteArrayElements(env, result, bufferPtrResult, 0);
	(*env)->ReleaseByteArrayElements(env, msg, bufferPtrMsg, JNI_ABORT);
	return ret == 0 ? result : NULL;
}

JNIEXPORT jobject JNICALL Java_org_hsbp_androsphinx_TpdkgContext_getInputSizes(JNIEnv *env, jobject ctxObj) {
	const jclass ctxClass = (*env)->FindClass(env, "org/hsbp/androsphinx/TpdkgContext");
	const jfieldID ctxField = (*env)->GetFieldID(env, ctxClass, "ctx", "J");
	const jlong ctxValue = (*env)->GetLongField(env, ctxObj, ctxField);
	const TP_DKG_TPState *state = (TP_DKG_TPState*)ctxValue;
	jbyte n = tpdkg_tpstate_n(state);
	size_t sizes[n];
	int ret = tpdkg_tp_input_sizes(state, sizes);
	jlongArray result = (*env)->NewLongArray(env, n);
	jlong* bufferResult = (*env)->GetLongArrayElements(env, result, NULL);
	for (int i = 0; i < n; i++) {
		bufferResult[i] = sizes[i];
	}
	(*env)->ReleaseLongArrayElements(env, result, bufferResult, 0);
	jclass clazz = (*env)->FindClass(env, "kotlin/Pair");
	jmethodID constructor = (*env)->GetMethodID(env, clazz, "<init>", "(Ljava/lang/Object;Ljava/lang/Object;)V");
	jclass boolCls = (*env)->FindClass(env, "java/lang/Boolean");
	jfieldID field = (*env)->GetStaticFieldID(env, boolCls, ret == 0 ? "FALSE" : "TRUE", "Ljava/lang/Boolean;");
	jobject boolObj = (*env)->GetStaticObjectField(env, boolCls, field);
	jobject pair = (*env)->NewObject(env, clazz, constructor, boolObj, result);
	return pair;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_TpdkgContext_getSessionId(JNIEnv *env, jobject ctxObj) {
	const jclass ctxClass = (*env)->FindClass(env, "org/hsbp/androsphinx/TpdkgContext");
	const jfieldID ctxField = (*env)->GetFieldID(env, ctxClass, "ctx", "J");
	const jlong ctxValue = (*env)->GetLongField(env, ctxObj, ctxField);
	const TP_DKG_TPState *state = (TP_DKG_TPState*)ctxValue;
	jbyteArray result = (*env)->NewByteArray(env, dkg_sessionid_SIZE);
	(*env)->SetByteArrayRegion(env, result, 0, dkg_sessionid_SIZE,
			(const jbyte*)tpdkg_tpstate_sessionid(state));
	return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_TpdkgContext_peerMessage(JNIEnv *env, jobject ctxObj, jbyteArray base, jbyte peer) {
	if (base == NULL) return NULL;

	const jclass ctxClass = (*env)->FindClass(env, "org/hsbp/androsphinx/TpdkgContext");
	const jfieldID ctxField = (*env)->GetFieldID(env, ctxClass, "ctx", "J");
	const jlong ctxValue = (*env)->GetLongField(env, ctxObj, ctxField);
	const TP_DKG_TPState *state = (TP_DKG_TPState*)ctxValue;
	
	jbyte *bufferPtrBase = (*env)->GetByteArrayElements(env, base, NULL);
	fprintf(stderr, "bufferPtrBase = %p\n", bufferPtrBase);
	jsize baseLen = (*env)->GetArrayLength(env, base);
	fprintf(stderr, "baseLen = %d\n", baseLen);
	fprintf(stderr, "ctx->prev = %d\n", state->prev);
	jbyte *msg;
	size_t size;
	jbyteArray result = NULL;

	if (tpdkg_tp_peer_msg(state, (const uint8_t*)bufferPtrBase, baseLen,
				peer, (const uint8_t**)&msg, &size) == 0) {
		fprintf(stderr, "msg = %p\n", msg);
		fprintf(stderr, "size = %zu\n", size);
		fprintf(stderr, "ctx->prev = %d\n", state->prev);
		result = (*env)->NewByteArray(env, size);
		(*env)->SetByteArrayRegion(env, result, 0, size, msg);
	}	

	(*env)->ReleaseByteArrayElements(env, base, bufferPtrBase, JNI_ABORT);
	return result;
}

JNIEXPORT void JNICALL Java_org_hsbp_androsphinx_TpdkgContext_dispose(JNIEnv *env, jobject ignore, jlong ctx, jlong buf) {
	fprintf(stderr, "dispose() called\n");
	TP_DKG_TPState *state = (TP_DKG_TPState*)ctx;
	free(state->commitments);
	fprintf(stderr, "commitments freed\n");
	free(state->complaints);
	free(state->encrypted_shares);
	free(state->cheaters);
	fprintf(stderr, "cheaters freed\n");
	free(state->peer_sig_pks);
	fprintf(stderr, "peer_sig_pks freed\n");
	free(state->peer_lt_pks);
	fprintf(stderr, "peer_lt_pks freed\n");
	free(state->last_ts);
	fprintf(stderr, "last_ts freed\n");
	free((void*)buf);
	fprintf(stderr, "dispose() finished\n");
}



JNIEXPORT jobject JNICALL Java_org_hsbp_androsphinx_Oprf_tpDkgPeerStart(JNIEnv *env, jobject ignore, jlong tsEpsilon, jbyteArray peerLongTermSecretKey, jbyteArray msg0) {
	if (msg0 == NULL || peerLongTermSecretKey == NULL) return NULL;

	const jbyte *buf = malloc(tpdkg_peerstate_size() + 32);
	fprintf(stderr, "buf = %p\n", buf);
	const jbyte *ctx = buf + (32 - ((unsigned long long)buf % 32));
	fprintf(stderr, "ctx = %p\n", ctx);

	TP_DKG_PeerState *state = (TP_DKG_PeerState*)ctx;

	jbyte* bufferPeerLongTermSecretKey = (*env)->GetByteArrayElements(env, peerLongTermSecretKey, NULL);
	jbyte* bufferMsg0 = (*env)->GetByteArrayElements(env, msg0, NULL);
	const int st_result = tpdkg_start_peer(state, tsEpsilon,
			(const uint8_t*)bufferPeerLongTermSecretKey,
			(const DKG_Message*)bufferMsg0);
	(*env)->ReleaseByteArrayElements(env, msg0, bufferMsg0, 0);
	(*env)->ReleaseByteArrayElements(env, peerLongTermSecretKey,
			bufferPeerLongTermSecretKey, 0);

	const jbyte n = tpdkg_peerstate_n(state);
	const jbyte t = tpdkg_peerstate_t(state);

	fprintf(stderr, "n = %d, t = %d\n", n, t);

	uint8_t (*peersSigPublicKeys)[][crypto_sign_PUBLICKEYBYTES] = malloc(n * crypto_sign_PUBLICKEYBYTES);
	uint8_t (*peersNoisePublicKeys)[][crypto_scalarmult_BYTES] = malloc(n * crypto_scalarmult_BYTES);
	Noise_XK_session_t *(*noiseOuts)[] = malloc(sizeof(void*) * n);
	Noise_XK_session_t *(* noiseIns)[] = malloc(sizeof(void*) * n);
	TOPRF_Share (* shares)[] = malloc(n * TOPRF_Share_BYTES);
	TOPRF_Share (*xshares)[] = malloc(n * TOPRF_Share_BYTES);
	uint8_t (*commitments)[][crypto_core_ristretto255_BYTES] = malloc(n * t * crypto_core_ristretto255_BYTES);
	uint16_t *complaints = malloc(n * n * 2);
	uint8_t *myComplaints = malloc(n);
	uint64_t *lastTimestamps = malloc(n * 8);

	tpdkg_peer_set_bufs(state, peersSigPublicKeys, peersNoisePublicKeys, noiseOuts, noiseIns, shares, xshares, commitments, complaints, myComplaints, lastTimestamps); 

	jclass ctxClass = (*env)->FindClass(env, "org/hsbp/androsphinx/TpdkgPeerContext");
	jmethodID ctxConstructor = (*env)->GetMethodID(env, ctxClass, "<init>", "(JJ)V");
	jobject ctxObj = (*env)->NewObject(env, ctxClass, ctxConstructor, ctx, buf);

	return ctxObj;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_TpdkgPeerContext_getSessionId(JNIEnv *env, jobject ctxObj) {
	const jclass ctxClass = (*env)->FindClass(env, "org/hsbp/androsphinx/TpdkgPeerContext");
	const jfieldID ctxField = (*env)->GetFieldID(env, ctxClass, "ctx", "J");
	const jlong ctxValue = (*env)->GetLongField(env, ctxObj, ctxField);
	const TP_DKG_PeerState *state = (TP_DKG_PeerState*)ctxValue;
	jbyteArray result = (*env)->NewByteArray(env, dkg_sessionid_SIZE);
	(*env)->SetByteArrayRegion(env, result, 0, dkg_sessionid_SIZE,
			(const jbyte*)tpdkg_peerstate_sessionid(state));
	return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_TpdkgPeerContext_getLongTermSecretKey(JNIEnv *env, jobject ctxObj) {
	const jclass ctxClass = (*env)->FindClass(env, "org/hsbp/androsphinx/TpdkgPeerContext");
	const jfieldID ctxField = (*env)->GetFieldID(env, ctxClass, "ctx", "J");
	const jlong ctxValue = (*env)->GetLongField(env, ctxObj, ctxField);
	const TP_DKG_PeerState *state = (TP_DKG_PeerState*)ctxValue;
	jbyteArray result = (*env)->NewByteArray(env, crypto_sign_SECRETKEYBYTES);
	(*env)->SetByteArrayRegion(env, result, 0, crypto_sign_SECRETKEYBYTES,
			(const jbyte*)tpdkg_peerstate_lt_sk(state));
	return result;
}

JNIEXPORT jboolean JNICALL Java_org_hsbp_androsphinx_TpdkgPeerContext_isNotDone(JNIEnv *env, jobject ctxObj) {
	const jclass ctxClass = (*env)->FindClass(env, "org/hsbp/androsphinx/TpdkgPeerContext");
	const jfieldID ctxField = (*env)->GetFieldID(env, ctxClass, "ctx", "J");
	const jlong ctxValue = (*env)->GetLongField(env, ctxObj, ctxField);
	const TP_DKG_PeerState *state = (TP_DKG_PeerState*)ctxValue;
	return tpdkg_peer_not_done(state) == 1 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_TpdkgPeerContext_getShare(JNIEnv *env, jobject ctxObj) {
	const jclass ctxClass = (*env)->FindClass(env, "org/hsbp/androsphinx/TpdkgPeerContext");
	const jfieldID ctxField = (*env)->GetFieldID(env, ctxClass, "ctx", "J");
	const jlong ctxValue = (*env)->GetLongField(env, ctxObj, ctxField);
	const TP_DKG_PeerState *state = (TP_DKG_PeerState*)ctxValue;

	jbyteArray result = (*env)->NewByteArray(env, TOPRF_Share_BYTES);
	(*env)->SetByteArrayRegion(env, result, 0, TOPRF_Share_BYTES,
			(const jbyte*)tpdkg_peerstate_share(state));
	return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_TpdkgPeerContext_next(JNIEnv *env, jobject ctxObj, jbyteArray msg) {
	if (msg == NULL) return NULL;
	const jclass ctxClass = (*env)->FindClass(env, "org/hsbp/androsphinx/TpdkgPeerContext");
	const jfieldID ctxField = (*env)->GetFieldID(env, ctxClass, "ctx", "J");
	const jlong ctxValue = (*env)->GetLongField(env, ctxObj, ctxField);
	TP_DKG_PeerState *state = (TP_DKG_PeerState*)ctxValue;
	const size_t inputSize = tpdkg_peer_input_size(state);
	jsize msgLen = (*env)->GetArrayLength(env, msg);
	if (msgLen != (jsize)inputSize) return NULL;
	jbyte *bufferPtrMsg = (*env)->GetByteArrayElements(env, msg, NULL);
	const size_t outputSize = tpdkg_peer_output_size(state);
	jbyteArray result = (*env)->NewByteArray(env, (jsize)outputSize);
	jbyte *bufferPtrResult = (*env)->GetByteArrayElements(env, result, NULL);

	int ret = tpdkg_peer_next(state, (const uint8_t*)bufferPtrMsg, inputSize,
			(uint8_t*)bufferPtrResult, outputSize);
	(*env)->ReleaseByteArrayElements(env, msg, bufferPtrMsg, JNI_ABORT);

	if (ret == 0) {
		(*env)->ReleaseByteArrayElements(env, result, bufferPtrResult, 0);
		return result;
	} else {
		(*env)->ReleaseByteArrayElements(env, result, bufferPtrResult, JNI_ABORT);
		return NULL;
	}
}

JNIEXPORT void JNICALL Java_org_hsbp_androsphinx_TpdkgPeerContext_dispose(JNIEnv *env, jobject ignore, jlong ctx, jlong buf) {
	fprintf(stderr, "PC dispose() called\n");
	TP_DKG_PeerState *state = (TP_DKG_PeerState*)ctx;
	free(state->peer_sig_pks);
	free(state->peer_noise_pks);
	free(state->noise_outs);
	free(state->noise_ins);
	free(state->shares);
	free(state->xshares);
	free(state->commitments);
	free(state->complaints);
	free(state->my_complaints);
	free(state->last_ts);
	free((void*)buf);
	fprintf(stderr, "PC dispose() finished\n");
}

/* ======== generic libsodium bindings ========= */

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sodium_genericHash(JNIEnv *env, jobject ignore, jbyteArray msg, jbyteArray salt, jint outlen) {
	if (outlen <= 0) return NULL;

	jbyte* bufferPtrMsg  = (*env)->GetByteArrayElements(env, msg,  NULL);
	jbyte* bufferPtrSalt = salt == NULL ? NULL : (*env)->GetByteArrayElements(env, salt, NULL);
	jsize msgLen = (*env)->GetArrayLength(env, msg);
	jsize saltLen = salt == NULL ? 0 : (*env)->GetArrayLength(env, salt);

	jbyteArray hash = (*env)->NewByteArray(env, outlen);
	jbyte* bufferPtrHash = (*env)->GetByteArrayElements(env, hash, NULL);

	crypto_generichash(bufferPtrHash, outlen,
			bufferPtrMsg, msgLen, bufferPtrSalt, saltLen);

	(*env)->ReleaseByteArrayElements(env, msg,  bufferPtrMsg, JNI_ABORT);
	if (salt != NULL) {
		(*env)->ReleaseByteArrayElements(env, salt, bufferPtrSalt, JNI_ABORT);
	}
	(*env)->ReleaseByteArrayElements(env, hash, bufferPtrHash, 0);

	return hash;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sodium_randomBytes(JNIEnv *env, jobject ignore, jint length) {
	jbyteArray result = (*env)->NewByteArray(env, length);
	jbyte* bufferPtrResult = (*env)->GetByteArrayElements(env, result, NULL);

	randombytes_buf(bufferPtrResult, length);

	(*env)->ReleaseByteArrayElements(env, result, bufferPtrResult, 0);

	return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sodium_cryptoSignSeedKeypair(JNIEnv *env, jobject ignore, jbyteArray seed) {
	unsigned char ignored_pk[crypto_sign_PUBLICKEYBYTES];

	jbyteArray result = (*env)->NewByteArray(env, crypto_sign_SECRETKEYBYTES);
	jbyte* bufferPtrResult = (*env)->GetByteArrayElements(env, result, NULL);
	jbyte* bufferPtrSeed = (*env)->GetByteArrayElements(env, seed, NULL);

	crypto_sign_seed_keypair(ignored_pk, bufferPtrResult, bufferPtrSeed);

	(*env)->ReleaseByteArrayElements(env, result, bufferPtrResult, 0);
	(*env)->ReleaseByteArrayElements(env, seed, bufferPtrSeed, JNI_ABORT);

	return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sodium_cryptoSignEd25519SkToPk(JNIEnv *env, jobject ignore, jbyteArray sk) {
	jbyteArray result = (*env)->NewByteArray(env, crypto_sign_PUBLICKEYBYTES);
	jbyte* bufferPtrResult = (*env)->GetByteArrayElements(env, result, NULL);
	jbyte* bufferPtrSk = (*env)->GetByteArrayElements(env, sk, NULL);

	crypto_sign_ed25519_sk_to_pk(bufferPtrResult, bufferPtrSk);

	(*env)->ReleaseByteArrayElements(env, result, bufferPtrResult, 0);
	(*env)->ReleaseByteArrayElements(env, sk, bufferPtrSk, JNI_ABORT);

	return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sodium_cryptoSignDetached(JNIEnv *env, jobject ignore, jbyteArray sk, jbyteArray msg) {
	jbyteArray result = (*env)->NewByteArray(env, crypto_sign_BYTES);
	jbyte* bufferPtrResult = (*env)->GetByteArrayElements(env, result, NULL);
	jbyte* bufferPtrSk = (*env)->GetByteArrayElements(env, sk, NULL);
	jbyte* bufferPtrMsg = (*env)->GetByteArrayElements(env, msg, NULL);
	jsize msgLen = (*env)->GetArrayLength(env, msg);

	unsigned long long ignored_siglen = crypto_sign_BYTES;

	crypto_sign_detached(bufferPtrResult, &ignored_siglen, bufferPtrMsg, msgLen, bufferPtrSk);

	(*env)->ReleaseByteArrayElements(env, result, bufferPtrResult, 0);
	(*env)->ReleaseByteArrayElements(env, sk, bufferPtrSk, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, msg, bufferPtrMsg, JNI_ABORT);

	return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sodium_cryptoAeadXchachaPoly1305IetfEasy(JNIEnv *env, jobject ignore, jbyteArray msg, jbyteArray ad, jbyteArray key) {
	jbyte* bufferPtrKey = (*env)->GetByteArrayElements(env, key, NULL);
	jbyte* bufferPtrMsg = (*env)->GetByteArrayElements(env, msg, NULL);
	jbyte* bufferPtrAd  = (*env)->GetByteArrayElements(env,  ad, NULL);
	jsize msgLen = (*env)->GetArrayLength(env, msg);
	jsize  adLen = (*env)->GetArrayLength(env,  ad);

	jbyteArray result = (*env)->NewByteArray(env, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + msgLen + crypto_aead_xchacha20poly1305_ietf_ABYTES);
	jbyte* bufferPtrResult = (*env)->GetByteArrayElements(env, result, NULL);

	randombytes_buf(bufferPtrResult, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

	int sodium_result = crypto_aead_xchacha20poly1305_ietf_encrypt(bufferPtrResult + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
			NULL, bufferPtrMsg, msgLen, bufferPtrAd, adLen, NULL, bufferPtrResult, bufferPtrKey);

	(*env)->ReleaseByteArrayElements(env, result, bufferPtrResult, sodium_result ? JNI_ABORT : 0);
	(*env)->ReleaseByteArrayElements(env,  ad, bufferPtrAd , JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, msg, bufferPtrMsg, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, key, bufferPtrKey, JNI_ABORT);

	return sodium_result ? NULL : result;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sodium_cryptoAeadXchachaPoly1305IetfOpenEasy(JNIEnv *env, jobject ignore, jbyteArray msg, jbyteArray ad, jbyteArray key) {
	jbyte* bufferPtrKey = (*env)->GetByteArrayElements(env, key, NULL);
	jbyte* bufferPtrMsg = (*env)->GetByteArrayElements(env, msg, NULL);
	jbyte* bufferPtrAd  = (*env)->GetByteArrayElements(env,  ad, NULL);
	jsize msgLen = (*env)->GetArrayLength(env, msg);
	jsize  adLen = (*env)->GetArrayLength(env,  ad);

	jbyteArray result = (*env)->NewByteArray(env, msgLen - (crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES));
	jbyte* bufferPtrResult = (*env)->GetByteArrayElements(env, result, NULL);

	int sodium_result = crypto_aead_xchacha20poly1305_ietf_decrypt(bufferPtrResult,
			NULL, NULL, bufferPtrMsg + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
			msgLen - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
			bufferPtrAd, adLen, bufferPtrMsg, bufferPtrKey);

	(*env)->ReleaseByteArrayElements(env, result, bufferPtrResult, sodium_result ? JNI_ABORT : 0);
	(*env)->ReleaseByteArrayElements(env,  ad, bufferPtrAd , JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, msg, bufferPtrMsg, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, key, bufferPtrKey, JNI_ABORT);

	return sodium_result ? NULL : result;
}

JNIEXPORT jbyteArray JNICALL Java_org_hsbp_androsphinx_Sodium_passwordHash(JNIEnv *env, jobject ignore, jint outlen, jbyteArray passwd, jbyteArray salt) {
	if (outlen <= 0 || passwd == NULL || salt == NULL ||
			(*env)->GetArrayLength(env, salt) != crypto_pwhash_SALTBYTES) return NULL;

	const jbyte* bufferPtrPasswd  = (*env)->GetByteArrayElements(env, passwd,  NULL);
	const jbyte* bufferPtrSalt = (*env)->GetByteArrayElements(env, salt, NULL);
	const jsize passwdLen = (*env)->GetArrayLength(env, passwd);
	jbyteArray hash = (*env)->NewByteArray(env, outlen);
	jbyte* bufferPtrHash = (*env)->GetByteArrayElements(env, hash, NULL);

	int sodium_result = crypto_pwhash((unsigned char * const)bufferPtrHash,
			(unsigned long long)outlen,
			(const char* const)bufferPtrPasswd,
			(unsigned long long)passwdLen,
			(const unsigned char* const)bufferPtrSalt,
			crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
			crypto_pwhash_ALG_DEFAULT);

	(*env)->ReleaseByteArrayElements(env, passwd,  bufferPtrPasswd, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, salt, bufferPtrSalt, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, hash, bufferPtrHash, sodium_result ? JNI_ABORT : 0);

	return sodium_result ? NULL : hash;
}
