package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

public class ParametersForThreefish implements CipherParameters {
    private int stateSize;
    private CipherParameters parameters;
    private long[] tweak;

    public ParametersForThreefish(
            CipherParameters    parameters,
            int                 stateSize,
            long[]              tweak)
    {
        this.stateSize = stateSize;
        this.parameters = parameters;
        if (tweak != null) {
            this.tweak = new long[2];
            this.tweak[0] = tweak[0];
            this.tweak[1] = tweak[1];
        }
    }

    /**
     * @return the stateSize
     */
    public int getStateSize() {
        return stateSize;
    }

    /**
     * @return the parameters
     */
    public CipherParameters getParameters() {
        return parameters;
    }

    /**
     * @return the tweak
     */
    public long[] getTweak() {
        return tweak;
    }

}
