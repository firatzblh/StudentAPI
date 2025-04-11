<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $data = $request->only(['name', 'email', 'password']);

        $validator = Validator::make($data, [
            'name'     => 'required|max:255',
            'email'    => 'required|email|unique:users,email',
            'password' => 'required|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status'  => false,
                'errors'  => $validator->errors()
            ], 422);
        }

        $user = new User([
            'name'     => $data['name'],
            'email'    => $data['email'],
            'password' => Hash::make($data['password']),
        ]);
        $user->save();

        $token = JWTAuth::fromUser($user);

        return response()->json([
            'status' => true,
            'message' => 'Registrasi berhasil',
            'token' => $token,
            'user' => $user,
        ], 201);
    }

    public function login(Request $request)
    {
        try {
            $credentials = $request->only(['email', 'password']);

            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json([
                    'status'  => false,
                    'message' => 'Login gagal! Email atau password salah.'
                ], 401);
            }

            return response()->json([
                'status'  => true,
                'message' => 'Login berhasil',
                'token'   => $token
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'status'  => false,
                'message' => 'Terjadi kesalahan saat login.',
                'error'   => $e->getMessage()
            ], 500);
        }
    }

    public function me()
    {
        $user = auth()->user();

        return response()->json([
            'status' => true,
            'data'   => $user
        ]);
    }

}