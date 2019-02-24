<?php

namespace SimpleAuth\Model;

interface AuthItemInterface
{
    /**
     * Get name
     *
     * @return string
     */
    public function getName();

    /**
     * Get key
     *
     * @return string
     */
    public function getKey();
}
