package com.cossacklabs.acra;

public interface CallbackListener<T> {
    void onComplete(T value);
}
