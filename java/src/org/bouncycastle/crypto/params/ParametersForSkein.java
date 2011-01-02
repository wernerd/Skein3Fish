package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

public class ParametersForSkein implements CipherParameters {

    public final static int Skein256 = 256;
    public final static int Skein512 = 512;
    public final static int Skein1024 = 1024;
    
    private int macSize;
    private int stateSize;
    private CipherParameters parameters;

    /**
     * Skein parameters for Skein MAC.
     * 
     * @param parameters
     *     This must be a KeyParameter instance that holds the key. 
     * @param stateSize
     *     The Skein state size to use.
     * @param macSize
     *     The requested Skein MAC output size in bits.
     */
    public ParametersForSkein(
            CipherParameters    parameters,
            int                 stateSize,
            int                 macSize)
    {
        this.macSize = macSize;
        this.stateSize = stateSize;
        this.parameters = parameters;
    }

    public int getMacSize()
    {
        return macSize;
    }

    public int getStateSize()
    {
        return stateSize;
    }

    public CipherParameters getParameters()
    {
        return parameters;
    }


}
